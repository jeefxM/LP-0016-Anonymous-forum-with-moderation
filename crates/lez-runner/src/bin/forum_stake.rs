//! Full staking lifecycle e2e (ADR-011) against a live LEZ sequencer.
//!
//! Demonstrates "register with a stake" and "slash claims the stake":
//!   1. Initialize → claims the registry state PDA and a registry-owned escrow
//!      PDA (asserts the escrow is owned by the registry, empty).
//!   2. Fund the escrow via the full chain: faucet → member vault →
//!      vault.Claim → member direct → authenticated_transfer → escrow. Asserts
//!      the escrow now holds the stake AND its owner is still the registry
//!      (the credit-preserves-owner property that makes the slash debit legal).
//!   3. Register member A → the guest's stake check passes only because the
//!      escrow is funded.
//!   4. Member A posts K times; N moderators sign a cert per post.
//!   5. Reconstruct the secret off-chain, submit Slash → asserts the member is
//!      revoked AND the escrow was debited into a fresh slasher account.
//!
//! Run on Hetzner:
//!   NSSA_WALLET_HOME_DIR=~/lez/wallet/configs/debug \
//!     cargo run --release --bin forum_stake -- <membership_registry.bin>

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use lez_runner::{
    account_of, balance_of, fund_escrow, initialize, load_program, poll_until, random_keypair,
    register, slash,
};
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
const STAKE: u128 = 1_000;

#[tokio::main]
async fn main() -> Result<()> {
    let wallet_core = WalletCore::from_env().map_err(|e| anyhow!("wallet from_env: {e:?}"))?;
    let program_path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: forum_stake <membership_registry.bin>"))?;
    let program = load_program(&program_path)?;
    let registry_id = program.id();
    println!("Program ID: {registry_id:?}");

    let mut rng = OsRng;
    let mod_secrets: Vec<SigningKey> = (0..M).map(|_| SigningKey::generate(&mut rng)).collect();
    let mod_pubs: Vec<[u8; 32]> = mod_secrets
        .iter()
        .map(|s| s.verifying_key().to_bytes())
        .collect();

    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes(),
    );

    // ── 1. Initialize: claims state + escrow PDAs ─────────────────────
    let config = ForumConfig {
        k_threshold: K,
        n_threshold: N,
        moderators: mod_pubs.clone(),
        stake_amount: STAKE,
    };
    println!("→ Initialize (K={K}, N={N}, M={M}, stake={STAKE})");
    let (pda, escrow, _) = initialize(&wallet_core, &program, seed, config).await?;
    println!("Registry PDA: {pda}");
    println!("Escrow PDA:   {escrow}");
    poll_until(&wallet_core, pda, "Initialize", 25, |s| s.next_leaf_index == 0).await?;

    let escrow0 = account_of(&wallet_core, escrow).await?;
    assert_eq!(
        escrow0.program_owner, registry_id,
        "escrow PDA must be claimed by the registry at Initialize"
    );
    assert_eq!(escrow0.balance, 0, "escrow starts empty");
    println!("  escrow claimed by registry, balance 0 ✓");

    // ── 2. Fund the escrow (faucet → vault → claim → escrow) ──────────
    println!("→ Stake {STAKE} into escrow");
    fund_escrow(&wallet_core, escrow, STAKE).await?;
    let escrow1 = account_of(&wallet_core, escrow).await?;
    assert_eq!(escrow1.balance, STAKE, "escrow must hold the stake");
    assert_eq!(
        escrow1.program_owner, registry_id,
        "crediting the escrow must preserve registry ownership (slash-debit legality)"
    );
    println!("  escrow funded: balance {STAKE}, owner still registry ✓");

    // ── 3. Register member A (stake check passes only when funded) ────
    let mut secret = [0u8; 32];
    secret[..16].copy_from_slice(&[0xA5u8; 16]);
    let commitment = shamir_commitment(&secret);
    let empty_path: MerklePath = [[0u8; 32]; TREE_DEPTH];
    println!("→ Register member A");
    register(&wallet_core, &program, pda, escrow, commitment, empty_path, 0).await?;
    let state1 = poll_until(&wallet_core, pda, "Register A", 25, |s| s.next_leaf_index == 1).await?;
    println!("  registered: tree_root={}", hex::encode(state1.tree_root));

    // ── 4. K strikes; N moderators sign a cert over each post's share ─
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
    println!("→ Built {} certs ({N}-of-{M} sigs each)", certs.len());

    let payload = build_slash_payload(&certs, &mod_pubs, N, K, state1.tree_root, 0, empty_path, &[])
        .map_err(|e| anyhow!("off-chain slash payload assembly: {e}"))?;
    assert_eq!(payload.commitment, commitment, "reconstructed commitment matches");

    // ── 5. Slash: revokes the member and pays the stake to the slasher ─
    let (_slasher_sk, slasher) = random_keypair();
    let slasher_before = balance_of(&wallet_core, slasher).await;
    println!("→ Slash (slasher {slasher})");
    slash(
        &wallet_core,
        &program,
        pda,
        escrow,
        slasher,
        payload.reconstructed_secret,
        payload.certificates,
        0,
        empty_path,
    )
    .await?;

    let state2 = poll_until(&wallet_core, pda, "Slash", 25, |s| !s.revocation_set.is_empty()).await?;
    assert!(
        state2.revocation_set.contains(&commitment),
        "member A must be in the revocation set"
    );
    assert!(
        state2.revoked_secrets.contains(&secret),
        "member A's secret must be published for retroactive deanonymization"
    );

    let escrow2 = balance_of(&wallet_core, escrow).await;
    let slasher_after = balance_of(&wallet_core, slasher).await;
    assert_eq!(escrow2, 0, "escrow drained by the stake claim");
    assert_eq!(
        slasher_after,
        slasher_before + STAKE,
        "slasher receives the stake"
    );

    println!(
        "\n✅ Staking e2e on live chain:\n   \
         register locked stake {STAKE} in escrow (registry-owned)\n   \
         slash revoked member A and paid the stake to the slasher\n   \
         escrow {STAKE} → 0, slasher {slasher_before} → {slasher_after}"
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
