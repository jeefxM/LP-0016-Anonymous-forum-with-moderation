//! End-to-end Register runner for the membership_registry program.
//!
//! Submits `Initialize` then `Register` against a running LEZ sequencer,
//! then queries the registry PDA and decodes the on-chain `ForumState` to
//! prove the tree_root advanced and next_leaf_index incremented.
//!
//! This is the live-chain counterpart to the pure-Rust `valid_registration`
//! test in `membership_registry_core`.
//!
//! Build + run on the Hetzner box (where ~/lez and a live sequencer exist):
//!   NSSA_WALLET_HOME_DIR=~/lez/wallet/configs/debug \
//!     cargo run --release --bin forum_register -- <path-to-membership_registry.bin>

use bincode::Options;
use common::transaction::NSSATransaction;
use membership_registry_core::{ForumConfig, ForumState, Instruction, MerklePath, TREE_DEPTH};
use nssa::{
    program::Program,
    public_transaction::{Message, WitnessSet},
    AccountId, PublicTransaction,
};
use nssa_core::program::PdaSeed;
use sequencer_service_rpc::RpcClient as _;
use wallet::WalletCore;

fn try_decode_state(bytes: &[u8]) -> Option<ForumState> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(bytes)
        .ok()
}

/// Poll the registry PDA until its data decodes into a `ForumState` whose
/// `next_leaf_index` is at least `min_index`. Blocks are produced roughly
/// every 15s, so we poll generously.
async fn poll_state(
    wallet_core: &WalletCore,
    pda: AccountId,
    min_index: u32,
    label: &str,
) -> ForumState {
    for attempt in 1..=20 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if let Ok(acct) = wallet_core.get_account_public(pda).await {
            if let Some(state) = try_decode_state(acct.data.as_ref()) {
                if state.next_leaf_index >= min_index {
                    return state;
                }
            }
        }
        if attempt % 5 == 0 {
            println!("  …still waiting for {label} (attempt {attempt}/20)");
        }
    }
    panic!("timed out waiting for {label} to land on chain");
}

async fn submit(
    wallet_core: &WalletCore,
    program: &Program,
    account_id: AccountId,
    instruction: Instruction,
    label: &str,
) {
    // The registry account is program-owned (claimed via PDA), so it needs
    // no user authorization. Like the no-auth hello_world example, both
    // nonces and signing keys are empty — the node requires their counts
    // to match.
    let nonces = vec![];
    let message = Message::try_new(program.id(), vec![account_id], nonces, instruction)
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

#[tokio::main]
async fn main() {
    let wallet_core = WalletCore::from_env().expect("NSSA_WALLET_HOME_DIR set + node reachable");

    let program_path = std::env::args_os()
        .nth(1)
        .expect("usage: forum_register <membership_registry.bin>")
        .into_string()
        .unwrap();
    let bytecode = std::fs::read(&program_path).expect("read program binary");
    let program = Program::new(bytecode).expect("valid program");
    println!("Program ID: {:?}", program.id());

    // Forum-instance PDA seed. In production this would be a hash of the
    // forum id; for the demo we derive a unique seed per run (from the
    // wall clock) so each invocation gets a fresh, uninitialised PDA.
    let mut seed = [0u8; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    seed[..16].copy_from_slice(&now);
    let pda = AccountId::for_public_pda(&program.id(), &PdaSeed::new(seed));
    println!("Registry PDA: {pda}");

    // ── 1. Initialize ────────────────────────────────────────────────
    let config = ForumConfig {
        k_threshold: 3,
        n_threshold: 2,
        moderators: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        stake_amount: 1_000,
    };
    println!("→ Initialize");
    submit(
        &wallet_core,
        &program,
        pda,
        Instruction::Initialize {
            config,
            seed,
        },
        "Initialize",
    )
    .await;

    let state0 = poll_state(&wallet_core, pda, 0, "Initialize").await;
    println!(
        "  after Initialize: next_leaf_index={}, tree_root={}",
        state0.next_leaf_index,
        hex::encode(state0.tree_root)
    );
    assert_eq!(state0.next_leaf_index, 0, "fresh registry starts at 0");

    // ── 2. Register member A at leaf 0 ───────────────────────────────
    // Empty tree → all-zero sibling path.
    let empty_path: MerklePath = [[0u8; 32]; TREE_DEPTH];
    let commitment_a = [0xAAu8; 32];
    println!("→ Register member A (leaf 0)");
    submit(
        &wallet_core,
        &program,
        pda,
        Instruction::Register {
            commitment: commitment_a,
            path_before: empty_path,
            leaf_index: 0,
        },
        "Register A",
    )
    .await;

    let state1 = poll_state(&wallet_core, pda, 1, "Register A").await;
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
}
