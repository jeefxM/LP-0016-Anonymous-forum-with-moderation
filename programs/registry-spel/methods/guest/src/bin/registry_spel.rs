//! Membership registry on the SPEL framework (ADR-012). Re-expresses the
//! hand-rolled guest as a `#[lez_program]` module; all real logic still lives
//! in `membership_registry_core` (pure Rust, shared with the host tests).
//!
//! Accounts:
//! - `state`  : per-forum PDA holding `ForumState`, seeded by the forum `seed`.
//! - `escrow` : registry-owned PDA seeded by the state account id; pools the
//!   members' native stake. `init` claims it for the program so `slash` can
//!   debit it directly (the program owns it).
//! - `slasher`: an existing account credited the stake on slash.

#![no_main]

use bincode::Options;
use membership_registry_core::{
    empty_tree_root, simulate_register, slash::verify_slash, ForumConfig as CoreForumConfig,
    ForumState, MerklePath, ModerationCertificateWire,
};
use nssa_core::account::{AccountWithMetadata, Data};
use spel_framework::prelude::*;

risc0_zkvm::guest::entry!(main);

fn encode_state(state: &ForumState) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(state)
        .expect("ForumState encoding must succeed")
}

fn decode_state(account: &AccountWithMetadata) -> Result<ForumState, SpelError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(account.account.data.as_ref())
        .map_err(|_| SpelError::custom(10, "ForumState data must decode"))
}

fn store_state(account: &mut AccountWithMetadata, state: &ForumState) -> Result<(), SpelError> {
    account.account.data =
        Data::try_from(encode_state(state)).map_err(|_| SpelError::custom(11, "state too big"))?;
    Ok(())
}

#[lez_program]
mod registry_spel {
    #[allow(unused_imports)]
    use super::*;

    /// Create a forum instance: claim the state PDA (holds `ForumState`) and a
    /// registry-owned escrow PDA (pools stake; empty at first). Config is
    /// passed as flat primitives (not a struct) so the auto-generated SPEL CLI
    /// can build the tx from IDL-native types; the handler assembles the core
    /// `ForumConfig` from them.
    #[instruction]
    pub fn initialize(
        #[account(init, pda = arg("seed"))] mut state: AccountWithMetadata,
        #[account(init, pda = account("state"))] escrow: AccountWithMetadata,
        k_threshold: u8,
        n_threshold: u8,
        moderators: Vec<[u8; 32]>,
        stake_amount: u128,
        seed: [u8; 32],
    ) -> SpelResult {
        let _ = &seed; // referenced by pda = arg("seed")
        let forum = ForumState {
            tree_root: empty_tree_root(),
            next_leaf_index: 0,
            revocation_set: Vec::new(),
            revoked_secrets: Vec::new(),
            config: CoreForumConfig {
                k_threshold,
                n_threshold,
                moderators,
                stake_amount,
            },
        };
        store_state(&mut state, &forum)?;
        Ok(SpelOutput::execute(vec![state, escrow], vec![]))
    }

    /// Register a member. Requires the escrow to already hold
    /// `stake_amount × members` (the member funds it with a native transfer
    /// before registering — ADR-011).
    #[instruction]
    pub fn register(
        #[account(mut, pda = arg("seed"))] mut state: AccountWithMetadata,
        #[account(pda = account("state"))] escrow: AccountWithMetadata,
        seed: [u8; 32],
        commitment: [u8; 32],
        path_before: Vec<[u8; 32]>,
        leaf_index: u32,
    ) -> SpelResult {
        let _ = &seed;
        let forum = decode_state(&state)?;

        let members_after = leaf_index as u128 + 1;
        let required = forum
            .config
            .stake_amount
            .checked_mul(members_after)
            .ok_or_else(|| SpelError::custom(20, "stake overflow"))?;
        if escrow.account.balance < required {
            return Err(SpelError::custom(
                21,
                "escrow underfunded: member must stake before registering",
            ));
        }

        let path: MerklePath = path_before
            .try_into()
            .map_err(|_| SpelError::custom(23, "merkle path wrong length"))?;
        let next = simulate_register(&forum, commitment, &path, leaf_index)
            .map_err(|e| SpelError::custom(22, format!("register rejected: {e}")))?;
        store_state(&mut state, &next)?;
        Ok(SpelOutput::execute(vec![state, escrow], vec![]))
    }

    /// Slash a member: verify the threshold evidence, record the revocation +
    /// the reconstructed secret (for retroactive deanonymization), and pay the
    /// stake out of the registry-owned escrow to the slasher.
    #[instruction]
    pub fn slash(
        #[account(mut, pda = arg("seed"))] mut state: AccountWithMetadata,
        #[account(mut, pda = account("state"))] mut escrow: AccountWithMetadata,
        #[account(mut)] mut slasher: AccountWithMetadata,
        seed: [u8; 32],
        reconstructed_secret: [u8; 32],
        certificates: Vec<ModerationCertificateWire>,
        leaf_index: u32,
        merkle_path: MerklePath,
    ) -> SpelResult {
        let _ = &seed;
        let mut forum = decode_state(&state)?;

        let commitment = verify_slash(
            &reconstructed_secret,
            &certificates,
            &forum.config,
            forum.tree_root,
            leaf_index,
            &merkle_path,
            &forum.revocation_set,
        )
        .map_err(|e| SpelError::custom(30, format!("slash rejected: {e:?}")))?;

        forum.revocation_set.push(commitment);
        forum.revoked_secrets.push(reconstructed_secret);
        store_state(&mut state, &forum)?;

        let stake = forum.config.stake_amount;
        escrow.account.balance = escrow
            .account
            .balance
            .checked_sub(stake)
            .ok_or_else(|| SpelError::custom(31, "escrow cannot cover the stake"))?;
        slasher.account.balance = slasher
            .account
            .balance
            .checked_add(stake)
            .ok_or_else(|| SpelError::custom(32, "slasher balance overflow"))?;

        Ok(SpelOutput::execute(vec![state, escrow, slasher], vec![]))
    }
}
