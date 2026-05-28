//! End-to-end Slash runner.
//!
//! Drives the full revocation lifecycle against a live LEZ sequencer:
//!   1. Initialize a forum instance with real Ed25519 moderator keys.
//!   2. Register member A.
//!   3. Member A "posts" K times — we compute the Shamir share for each
//!      post and have N moderators sign a certificate over it.
//!   4. Aggregate K certs, reconstruct the secret (off-chain), build the
//!      slash payload, and submit `Instruction::Slash`.
//!   5. Query the registry and assert member A's commitment is now in the
//!      on-chain revocation set.
//!
//! This is the live-chain counterpart to the `slash_submission` /
//! `post_rejection_after_revocation` tests.
//!
//! Build + run on Hetzner:
//!   NSSA_WALLET_HOME_DIR=~/lez/wallet/configs/debug \
//!     cargo run --release --bin forum_slash -- <path-to-membership_registry.bin>

use bincode::Options;
use common::transaction::NSSATransaction;
use ed25519_dalek::SigningKey;
use membership_registry_core::{
    ForumConfig, ForumState, Instruction, MerklePath, TREE_DEPTH,
};
use moderation_cert::sign_vote;
use nssa::{
    program::Program,
    public_transaction::{Message, WitnessSet},
    AccountId, PublicTransaction,
};
use nssa_core::program::PdaSeed;
use post_proof_core::shamir;
use rand::rngs::OsRng;
use sequencer_service_rpc::RpcClient as _;
use slash_evidence::build_slash_payload;
use wallet::WalletCore;

const K: u8 = 3;
const N: u8 = 2;
const M: usize = 5;

fn try_decode_state(bytes: &[u8]) -> Option<ForumState> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(bytes)
        .ok()
}

async fn submit(
    wallet_core: &WalletCore,
    program: &Program,
    account_id: AccountId,
    instruction: Instruction,
    label: &str,
) {
    let message = Message::try_new(program.id(), vec![account_id], vec![], instruction)
        .expect("message construction");
    let witness_set = WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);
    let resp = wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .unwrap_or_else(|e| panic!("{label} submit failed: {e}"));
    println!("  {label} submitted: {resp:?}");
}

async fn poll_until<F>(
    wallet_core: &WalletCore,
    pda: AccountId,
    label: &str,
    pred: F,
) -> ForumState
where
    F: Fn(&ForumState) -> bool,
{
    for attempt in 1..=25 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if let Ok(acct) = wallet_core.get_account_public(pda).await {
            if let Some(state) = try_decode_state(acct.data.as_ref()) {
                if pred(&state) {
                    return state;
                }
            }
        }
        if attempt % 5 == 0 {
            println!("  …waiting for {label} (attempt {attempt}/25)");
        }
    }
    panic!("timed out waiting for {label}");
}

#[tokio::main]
async fn main() {
    let wallet_core = WalletCore::from_env().expect("NSSA_WALLET_HOME_DIR set + node reachable");
    let program_path = std::env::args_os()
        .nth(1)
        .expect("usage: forum_slash <membership_registry.bin>")
        .into_string()
        .unwrap();
    let program = Program::new(std::fs::read(&program_path).expect("read bin")).expect("program");
    println!("Program ID: {:?}", program.id());

    // Real moderator keypairs.
    let mut rng = OsRng;
    let mod_secrets: Vec<SigningKey> = (0..M).map(|_| SigningKey::generate(&mut rng)).collect();
    let mod_pubs: Vec<[u8; 32]> = mod_secrets.iter().map(|s| s.verifying_key().to_bytes()).collect();

    // Unique PDA per run.
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes(),
    );
    let pda = AccountId::for_public_pda(&program.id(), &PdaSeed::new(seed));
    println!("Registry PDA: {pda}");

    // ── 1. Initialize with real moderators ───────────────────────────
    let config = ForumConfig {
        k_threshold: K,
        n_threshold: N,
        moderators: mod_pubs.clone(),
        stake_amount: 1_000,
    };
    println!("→ Initialize (K={K}, N={N}, M={M})");
    submit(&wallet_core, &program, pda, Instruction::Initialize { config: config.clone(), seed }, "Initialize").await;
    let state0 = poll_until(&wallet_core, pda, "Initialize", |s| s.next_leaf_index == 0).await;

    // ── 2. Register member A (canonical Fr-encoded secret) ───────────
    let mut secret = [0u8; 32];
    secret[..16].copy_from_slice(&[0xA5u8; 16]);
    let commitment = shamir_commitment(&secret);
    let empty_path: MerklePath = [[0u8; 32]; TREE_DEPTH];
    println!("→ Register member A");
    submit(
        &wallet_core,
        &program,
        pda,
        Instruction::Register { commitment, path_before: empty_path, leaf_index: 0 },
        "Register A",
    )
    .await;
    let state1 = poll_until(&wallet_core, pda, "Register A", |s| s.next_leaf_index == 1).await;
    println!("  registered: tree_root={}", hex::encode(state1.tree_root));
    assert_ne!(state1.tree_root, state0.tree_root);

    // ── 3. Member A posts K times; moderators sign certs over shares ──
    let content_ids = [[11u8; 32], [22u8; 32], [33u8; 32]];
    let certs: Vec<_> = content_ids
        .iter()
        .enumerate()
        .map(|(i, cid)| {
            let (x_fr, y_fr) = shamir::compute_share(&secret, K as usize, cid);
            let share_x = shamir::fr_to_bytes(&x_fr);
            let share_y = shamir::fr_to_bytes(&y_fr);
            let votes: Vec<_> = mod_secrets
                .iter()
                .take(N as usize)
                .map(|sk| sign_vote(sk, *cid, i as u8, share_x, share_y))
                .collect();
            moderation_cert::aggregate(&votes, N).expect("aggregate")
        })
        .collect();
    println!("→ Built {} certs ({}-of-{} sigs each)", certs.len(), N, M);

    // ── 4. Reconstruct secret off-chain + build slash payload ─────────
    let payload = build_slash_payload(
        &certs,
        &mod_pubs,
        N,
        K,
        state1.tree_root,
        0,
        empty_path,
        &[],
    )
    .expect("off-chain slash payload assembly");
    assert_eq!(payload.commitment, commitment, "reconstructed commitment matches member A");
    println!("  off-chain reconstruction OK, commitment matches");

    // ── 5. Submit Slash on-chain ──────────────────────────────────────
    println!("→ Slash");
    submit(
        &wallet_core,
        &program,
        pda,
        Instruction::Slash {
            reconstructed_secret: payload.reconstructed_secret,
            certificates: payload.certificates,
            leaf_index: 0,
            merkle_path: empty_path,
        },
        "Slash",
    )
    .await;

    let state2 = poll_until(&wallet_core, pda, "Slash", |s| !s.revocation_set.is_empty()).await;
    assert!(
        state2.revocation_set.contains(&commitment),
        "member A's commitment must be in the on-chain revocation set"
    );

    println!(
        "\n✅ Slash e2e on live chain: revocation_set now contains member A's commitment ({} entry)",
        state2.revocation_set.len()
    );
}

/// commitment_of = sha256("commit" || secret). Matches the guest + slash
/// verifier convention. (Re-derived here to avoid importing the host crate's
/// private helper.)
fn shamir_commitment(secret: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"commit");
    h.update(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}
