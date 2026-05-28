//! Chain helpers shared by the live-chain runner binaries and the proof
//! daemon (ADR-004). Everything that builds, submits, polls, or decodes a
//! membership_registry transaction lives here so the daemon and the
//! `forum_register` / `forum_slash` bins use byte-identical logic.
//!
//! Path-deps the LEZ sibling checkout; only builds on the Hetzner box.

use std::time::Duration;

use anyhow::{anyhow, Result};
use bincode::Options;
use common::transaction::NSSATransaction;
use membership_registry_core::{
    ForumConfig, ForumState, Instruction, MerklePath, ModerationCertificateWire,
};
use nssa::{
    public_transaction::{Message, WitnessSet},
    PublicTransaction,
};
use nssa_core::program::PdaSeed;
use sequencer_service_rpc::RpcClient as _;

// Re-export the LEZ types the daemon needs so it depends only on lez-runner,
// not on the LEZ sibling checkout paths directly. These are also in scope
// for this module.
pub use nssa::{program::Program, AccountId};
pub use wallet::WalletCore;

/// Load a compiled program binary from disk.
pub fn load_program(path: &str) -> Result<Program> {
    let bytecode = std::fs::read(path).map_err(|e| anyhow!("read program binary {path}: {e}"))?;
    Program::new(bytecode).map_err(|e| anyhow!("invalid program binary: {e:?}"))
}

/// Derive the registry PDA `AccountId` for a forum-instance seed.
pub fn pda_for_seed(program: &Program, seed: [u8; 32]) -> AccountId {
    AccountId::for_public_pda(&program.id(), &PdaSeed::new(seed))
}

/// Decode a PDA account's raw `data` into a `ForumState`. Returns `None`
/// while the account is still uninitialised / not yet on chain.
pub fn decode_state(bytes: &[u8]) -> Option<ForumState> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(bytes)
        .ok()
}

/// Single, non-blocking read of the registry state. `Ok(None)` means the
/// account isn't on chain yet or doesn't decode.
pub async fn load_state(wallet_core: &WalletCore, pda: AccountId) -> Result<Option<ForumState>> {
    match wallet_core.get_account_public(pda).await {
        Ok(acct) => Ok(decode_state(acct.data.as_ref())),
        Err(_) => Ok(None),
    }
}

/// Submit one instruction against the registry PDA. The registry account is
/// program-owned (claimed via PDA), so it needs no user authorization: both
/// nonces and signing keys are empty (the node requires their counts to
/// match — same shape as the no-auth hello_world example). Returns the
/// sequencer's transaction hash as a string.
pub async fn submit(
    wallet_core: &WalletCore,
    program: &Program,
    account_id: AccountId,
    instruction: Instruction,
) -> Result<String> {
    let nonces = vec![];
    let message = Message::try_new(program.id(), vec![account_id], nonces, instruction)
        .map_err(|e| anyhow!("message construction: {e:?}"))?;
    let witness_set = WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);
    let hash = wallet_core
        .sequencer_client
        .send_transaction(NSSATransaction::Public(tx))
        .await
        .map_err(|e| anyhow!("submit failed: {e}"))?;
    Ok(format!("{hash:?}"))
}

/// Poll the registry PDA until `pred` holds, ~3s between attempts (blocks
/// land roughly every 15s). Errors if it never satisfies `pred`.
pub async fn poll_until<F>(
    wallet_core: &WalletCore,
    pda: AccountId,
    label: &str,
    max_attempts: u32,
    pred: F,
) -> Result<ForumState>
where
    F: Fn(&ForumState) -> bool,
{
    for attempt in 1..=max_attempts {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if let Some(state) = load_state(wallet_core, pda).await? {
            if pred(&state) {
                return Ok(state);
            }
        }
        if attempt % 5 == 0 {
            eprintln!("  …waiting for {label} (attempt {attempt}/{max_attempts})");
        }
    }
    Err(anyhow!("timed out waiting for {label}"))
}

/// `Initialize` a fresh forum instance. Returns the registry PDA and the tx
/// hash. The PDA is derived from `seed`; callers that want a deterministic,
/// re-loadable instance should derive `seed` from a stable forum id.
pub async fn initialize(
    wallet_core: &WalletCore,
    program: &Program,
    seed: [u8; 32],
    config: ForumConfig,
) -> Result<(AccountId, String)> {
    let pda = pda_for_seed(program, seed);
    let hash = submit(
        wallet_core,
        program,
        pda,
        Instruction::Initialize { config, seed },
    )
    .await?;
    Ok((pda, hash))
}

/// Submit a `Register`. `path_before` is the empty-leaf sibling path at
/// `leaf_index` against the current `tree_root` — the caller computes it
/// (ADR-004: the daemon does not track the tree). Returns the tx hash.
pub async fn register(
    wallet_core: &WalletCore,
    program: &Program,
    pda: AccountId,
    commitment: [u8; 32],
    path_before: MerklePath,
    leaf_index: u32,
) -> Result<String> {
    submit(
        wallet_core,
        program,
        pda,
        Instruction::Register {
            commitment,
            path_before,
            leaf_index,
        },
    )
    .await
}

/// Submit a `Slash`. The verifier re-checks every field on chain (ADR-008).
/// Returns the tx hash.
pub async fn slash(
    wallet_core: &WalletCore,
    program: &Program,
    pda: AccountId,
    reconstructed_secret: [u8; 32],
    certificates: Vec<ModerationCertificateWire>,
    leaf_index: u32,
    merkle_path: MerklePath,
) -> Result<String> {
    submit(
        wallet_core,
        program,
        pda,
        Instruction::Slash {
            reconstructed_secret,
            certificates,
            leaf_index,
            merkle_path,
        },
    )
    .await
}
