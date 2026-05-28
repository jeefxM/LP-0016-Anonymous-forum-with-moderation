//! End-to-end Register runner for the membership_registry program.
//!
//! Submits `Initialize` then `Register` against a running LEZ sequencer,
//! then queries the registry PDA and decodes the on-chain `ForumState` to
//! prove the tree_root advanced and next_leaf_index incremented.
//!
//! This is the live-chain counterpart to the pure-Rust `valid_registration`
//! test in `membership_registry_core`. The chain plumbing lives in the
//! `lez_runner` library; this bin is a thin demo wrapper.
//!
//! Build + run on the Hetzner box (where ~/lez and a live sequencer exist):
//!   NSSA_WALLET_HOME_DIR=~/lez/wallet/configs/debug \
//!     cargo run --release --bin forum_register -- <path-to-membership_registry.bin>

use anyhow::{anyhow, Result};
use lez_runner::{fund_escrow, initialize, load_program, poll_until, register};
use membership_registry_core::{ForumConfig, MerklePath, TREE_DEPTH};
use wallet::WalletCore;

#[tokio::main]
async fn main() -> Result<()> {
    let wallet_core = WalletCore::from_env().map_err(|e| anyhow!("wallet from_env: {e:?}"))?;

    let program_path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: forum_register <membership_registry.bin>"))?;
    let program = load_program(&program_path)?;
    println!("Program ID: {:?}", program.id());

    // Unique seed per run (wall clock) so each invocation gets a fresh,
    // uninitialised PDA.
    let mut seed = [0u8; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    seed[..16].copy_from_slice(&now);

    // ── 1. Initialize ────────────────────────────────────────────────
    let config = ForumConfig {
        k_threshold: 3,
        n_threshold: 2,
        moderators: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        stake_amount: 1_000,
    };
    let stake = config.stake_amount;
    println!("→ Initialize");
    let (pda, escrow, _) = initialize(&wallet_core, &program, seed, config).await?;
    println!("Registry PDA: {pda}");
    println!("Escrow PDA:   {escrow}");

    let state0 = poll_until(&wallet_core, pda, "Initialize", 20, |s| s.next_leaf_index == 0).await?;
    println!(
        "  after Initialize: next_leaf_index={}, tree_root={}",
        state0.next_leaf_index,
        hex::encode(state0.tree_root)
    );

    // ── 2. Fund the escrow so Register's stake check passes (ADR-011) ──
    println!("→ Fund escrow with stake {stake}");
    fund_escrow(&wallet_core, escrow, stake).await?;

    // ── 3. Register member A at leaf 0 (empty tree → zero sibling path) ─
    let empty_path: MerklePath = [[0u8; 32]; TREE_DEPTH];
    let commitment_a = [0xAAu8; 32];
    println!("→ Register member A (leaf 0)");
    register(&wallet_core, &program, pda, escrow, commitment_a, empty_path, 0).await?;

    let state1 = poll_until(&wallet_core, pda, "Register A", 20, |s| s.next_leaf_index >= 1).await?;
    println!(
        "  after Register A: next_leaf_index={}, tree_root={}",
        state1.next_leaf_index,
        hex::encode(state1.tree_root)
    );
    assert_eq!(state1.next_leaf_index, 1, "leaf index advanced");
    assert_ne!(
        state1.tree_root, state0.tree_root,
        "tree_root changed after registration"
    );

    println!("\n✅ Register e2e on live chain: tree_root advanced, next_leaf_index = 1");
    Ok(())
}
