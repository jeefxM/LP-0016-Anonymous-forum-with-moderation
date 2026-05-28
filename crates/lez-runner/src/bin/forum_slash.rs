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
//! `post_rejection_after_revocation` tests. The chain plumbing lives in the
//! `lez_runner` library; this bin is a thin demo wrapper.
//!
//! Build + run on Hetzner:
//!   NSSA_WALLET_HOME_DIR=~/lez/wallet/configs/debug \
//!     cargo run --release --bin forum_slash -- <path-to-membership_registry.bin>

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use lez_runner::{initialize, load_program, poll_until, register, slash};
use membership_registry_core::{ForumConfig, MerklePath, TREE_DEPTH};
use moderation_cert::sign_vote;
use post_proof_core::shamir;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use slash_evidence::build_slash_payload;
use wallet::WalletCore;

const K: u8 = 3;
const N: u8 = 2;
const M: usize = 5;

#[tokio::main]
async fn main() -> Result<()> {
    let wallet_core = WalletCore::from_env().map_err(|e| anyhow!("wallet from_env: {e:?}"))?;
    let program_path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: forum_slash <membership_registry.bin>"))?;
    let program = load_program(&program_path)?;
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

    // ── 1. Initialize with real moderators ───────────────────────────
    let config = ForumConfig {
        k_threshold: K,
        n_threshold: N,
        moderators: mod_pubs.clone(),
        stake_amount: 1_000,
    };
    println!("→ Initialize (K={K}, N={N}, M={M})");
    let (pda, _) = initialize(&wallet_core, &program, seed, config).await?;
    println!("Registry PDA: {pda}");
    let state0 = poll_until(&wallet_core, pda, "Initialize", 25, |s| s.next_leaf_index == 0).await?;

    // ── 2. Register member A (canonical Fr-encoded secret) ───────────
    let mut secret = [0u8; 32];
    secret[..16].copy_from_slice(&[0xA5u8; 16]);
    let commitment = shamir_commitment(&secret);
    let empty_path: MerklePath = [[0u8; 32]; TREE_DEPTH];
    println!("→ Register member A");
    register(&wallet_core, &program, pda, commitment, empty_path, 0).await?;
    let state1 = poll_until(&wallet_core, pda, "Register A", 25, |s| s.next_leaf_index == 1).await?;
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
    let payload = build_slash_payload(&certs, &mod_pubs, N, K, state1.tree_root, 0, empty_path, &[])
        .map_err(|e| anyhow!("off-chain slash payload assembly: {e}"))?;
    assert_eq!(payload.commitment, commitment, "reconstructed commitment matches member A");
    println!("  off-chain reconstruction OK, commitment matches");

    // ── 5. Submit Slash on-chain ──────────────────────────────────────
    println!("→ Slash");
    slash(
        &wallet_core,
        &program,
        pda,
        payload.reconstructed_secret,
        payload.certificates,
        0,
        empty_path,
    )
    .await?;

    let state2 = poll_until(&wallet_core, pda, "Slash", 25, |s| !s.revocation_set.is_empty()).await?;
    assert!(
        state2.revocation_set.contains(&commitment),
        "member A's commitment must be in the on-chain revocation set"
    );

    println!(
        "\n✅ Slash e2e on live chain: revocation_set now contains member A's commitment ({} entry)",
        state2.revocation_set.len()
    );
    Ok(())
}

/// commitment_of = sha256("commit" || secret). Matches the guest + slash
/// verifier convention.
fn shamir_commitment(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"commit");
    h.update(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}
