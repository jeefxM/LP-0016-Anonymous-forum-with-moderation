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
    staking, ForumConfig, ForumState, Instruction, MerklePath, ModerationCertificateWire,
};
use nssa::{
    public_transaction::{Message, WitnessSet},
    PrivateKey, PublicKey, PublicTransaction,
};
use nssa_core::{
    account::{Account, Nonce},
    program::{PdaSeed, ProgramId},
};
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

/// Submit one transaction. `signers` are the private keys that authorize it;
/// the nonce vector is fetched per-signer (the node matches `nonces.len()` to
/// the number of signers, not to `account_ids` — verified against the AMM
/// mixed-auth tests). Program-owned PDA accounts need no signer, so registry
/// calls pass `&[]` (empty nonces + empty witness). Returns the sequencer's
/// transaction hash as a string.
async fn submit_tx<T: serde::Serialize>(
    wallet_core: &WalletCore,
    program_id: ProgramId,
    account_ids: Vec<AccountId>,
    signers: &[&PrivateKey],
    instruction: T,
) -> Result<String> {
    let nonces: Vec<Nonce> = if signers.is_empty() {
        vec![]
    } else {
        let signer_ids: Vec<AccountId> = signers
            .iter()
            .map(|k| AccountId::from(&PublicKey::new_from_private_key(k)))
            .collect();
        wallet_core
            .get_accounts_nonces(signer_ids)
            .await
            .map_err(|e| anyhow!("get_accounts_nonces: {e}"))?
    };
    let message = Message::try_new(program_id, account_ids, nonces, instruction)
        .map_err(|e| anyhow!("message construction: {e:?}"))?;
    let witness_set = WitnessSet::for_message(&message, signers);
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

/// The registry-owned stake-escrow PDA for a forum instance, derived from the
/// state PDA's id (mirrors the guest's `escrow_account_id`, ADR-011).
pub fn escrow_for_state(program: &Program, state_pda: &AccountId) -> AccountId {
    let seed = staking::escrow_seed(state_pda.value());
    AccountId::for_public_pda(&program.id(), &PdaSeed::new(seed))
}

/// `Initialize` a fresh forum instance. Claims the state PDA and the escrow
/// PDA. Returns `(state_pda, escrow_pda, tx_hash)`. The PDAs are derived from
/// `seed`; callers that want a deterministic, re-loadable instance should
/// derive `seed` from a stable forum id.
pub async fn initialize(
    wallet_core: &WalletCore,
    program: &Program,
    seed: [u8; 32],
    config: ForumConfig,
) -> Result<(AccountId, AccountId, String)> {
    let pda = pda_for_seed(program, seed);
    let escrow = escrow_for_state(program, &pda);
    let hash = submit_tx(
        wallet_core,
        program.id(),
        vec![pda, escrow],
        &[],
        Instruction::Initialize { config, seed },
    )
    .await?;
    Ok((pda, escrow, hash))
}

/// Submit a `Register`. `path_before` is the empty-leaf sibling path at
/// `leaf_index` against the current `tree_root` — the caller computes it
/// (ADR-004: the daemon does not track the tree). The escrow must already
/// hold `stake_amount × members` (the guest asserts it). Returns the tx hash.
pub async fn register(
    wallet_core: &WalletCore,
    program: &Program,
    pda: AccountId,
    escrow: AccountId,
    commitment: [u8; 32],
    path_before: MerklePath,
    leaf_index: u32,
) -> Result<String> {
    submit_tx(
        wallet_core,
        program.id(),
        vec![pda, escrow],
        &[],
        Instruction::Register {
            commitment,
            path_before,
            leaf_index,
        },
    )
    .await
}

/// Submit a `Slash`. The verifier re-checks every field on chain (ADR-008),
/// then pays `stake_amount` out of the registry-owned escrow to `slasher`.
/// Returns the tx hash.
#[allow(clippy::too_many_arguments)]
pub async fn slash(
    wallet_core: &WalletCore,
    program: &Program,
    pda: AccountId,
    escrow: AccountId,
    slasher: AccountId,
    reconstructed_secret: [u8; 32],
    certificates: Vec<ModerationCertificateWire>,
    leaf_index: u32,
    merkle_path: MerklePath,
) -> Result<String> {
    submit_tx(
        wallet_core,
        program.id(),
        vec![pda, escrow, slasher],
        &[],
        Instruction::Slash {
            reconstructed_secret,
            certificates,
            leaf_index,
            merkle_path,
        },
    )
    .await
}

// ──────────────────────────────────────────────────────────────────────
// Staking funding helpers (ADR-011). Native value lives in per-owner vaults;
// the chain to get spendable balance into the registry-owned escrow is:
// faucet → member vault → vault.Claim → member direct → authenticated_transfer
// → escrow. All accounts here are standalone keypairs; no wallet keychain is
// touched (we only borrow the wallet's sequencer client + nonce/account reads).
// ──────────────────────────────────────────────────────────────────────

/// A fresh standalone keypair and its public `AccountId`. Used for members
/// and the slasher — neither needs to live in the wallet's keychain.
pub fn random_keypair() -> (PrivateKey, AccountId) {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(sk) = PrivateKey::try_new(bytes) {
            let id = AccountId::from(&PublicKey::new_from_private_key(&sk));
            return (sk, id);
        }
    }
}

/// The system faucet PDA (holds the genesis native supply).
pub fn faucet_pda() -> AccountId {
    faucet_core::compute_faucet_account_id(Program::faucet().id())
}

/// An owner's vault PDA under the system vault program.
pub fn vault_for(owner: AccountId) -> AccountId {
    vault_core::compute_vault_account_id(Program::vault().id(), owner)
}

/// Read an account's native balance, or 0 if it isn't on chain yet.
pub async fn balance_of(wallet_core: &WalletCore, id: AccountId) -> u128 {
    wallet_core
        .get_account_public(id)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// Read a full account (balance + program_owner), erroring if absent.
pub async fn account_of(wallet_core: &WalletCore, id: AccountId) -> Result<Account> {
    wallet_core
        .get_account_public(id)
        .await
        .map_err(|e| anyhow!("get_account_public({id}): {e}"))
}

/// Permissionless faucet drip into `recipient`'s vault. The faucet PDA
/// self-authorizes (no signer); both accounts are program-owned.
pub async fn faucet_to_vault(
    wallet_core: &WalletCore,
    recipient: AccountId,
    amount: u128,
) -> Result<String> {
    submit_tx(
        wallet_core,
        Program::faucet().id(),
        vec![faucet_pda(), vault_for(recipient)],
        &[],
        faucet_core::Instruction::Transfer {
            vault_program_id: Program::vault().id(),
            recipient_id: recipient,
            amount,
        },
    )
    .await
}

/// Owner-signed `vault.Claim`: moves `amount` from the owner's vault into the
/// owner's direct balance. The credit auto-claims the owner under the
/// authenticated_transfer program, making it spendable thereafter.
pub async fn vault_claim(
    wallet_core: &WalletCore,
    owner_sk: &PrivateKey,
    owner: AccountId,
    amount: u128,
) -> Result<String> {
    submit_tx(
        wallet_core,
        Program::vault().id(),
        vec![owner, vault_for(owner)],
        &[owner_sk],
        vault_core::Instruction::Claim { amount },
    )
    .await
}

/// Sender-signed native transfer (authenticated_transfer). Crediting a
/// non-default-owned recipient (e.g. the registry escrow) preserves its owner
/// — confirmed in the guest, this is what makes the escrow direct-debit on
/// slash legal.
pub async fn transfer_native(
    wallet_core: &WalletCore,
    sender_sk: &PrivateKey,
    sender: AccountId,
    recipient: AccountId,
    amount: u128,
) -> Result<String> {
    submit_tx(
        wallet_core,
        Program::authenticated_transfer_program().id(),
        vec![sender, recipient],
        &[sender_sk],
        authenticated_transfer_core::Instruction::Transfer { amount },
    )
    .await
}

/// Poll an account until `pred` holds (or time out), ~3s between attempts.
pub async fn poll_account_until<F>(
    wallet_core: &WalletCore,
    id: AccountId,
    label: &str,
    max_attempts: u32,
    pred: F,
) -> Result<Account>
where
    F: Fn(&Account) -> bool,
{
    for attempt in 1..=max_attempts {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if let Ok(acct) = wallet_core.get_account_public(id).await {
            if pred(&acct) {
                return Ok(acct);
            }
        }
        if attempt % 5 == 0 {
            eprintln!("  …waiting for {label} (attempt {attempt}/{max_attempts})");
        }
    }
    Err(anyhow!("timed out waiting for {label}"))
}

/// Full funding choreography for one stake: mint a fresh member, drip the
/// faucet into its vault, claim it to a spendable direct balance, then stake
/// `amount` into the forum's `escrow`. Blocks until each leg lands. Returns
/// the member keypair (so a caller can register the same identity).
pub async fn fund_escrow(
    wallet_core: &WalletCore,
    escrow: AccountId,
    amount: u128,
) -> Result<(PrivateKey, AccountId)> {
    let (member_sk, member) = random_keypair();
    let member_vault = vault_for(member);

    eprintln!("  funding member {member}");
    faucet_to_vault(wallet_core, member, amount).await?;
    poll_account_until(wallet_core, member_vault, "faucet→vault", 25, |a| {
        a.balance >= amount
    })
    .await?;

    vault_claim(wallet_core, &member_sk, member, amount).await?;
    poll_account_until(wallet_core, member, "vault.Claim", 25, |a| a.balance >= amount).await?;

    let before = balance_of(wallet_core, escrow).await;
    transfer_native(wallet_core, &member_sk, member, escrow, amount).await?;
    poll_account_until(wallet_core, escrow, "stake→escrow", 25, |a| {
        a.balance >= before + amount
    })
    .await?;

    Ok((member_sk, member))
}
