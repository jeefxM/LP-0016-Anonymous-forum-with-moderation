//! LEZ program: per-forum membership registry (with staking, ADR-011).
//!
//! Account model
//! =============
//! - `Initialize` claims two PDAs of this program: the **state** account
//!   (holds `ForumState`, seeded by the forum id) and a **stake escrow**
//!   account (seeded by `staking::escrow_seed(state_account_id)`), which
//!   pools members' native stake. Pre-states: `[state, escrow]`.
//! - `Register` requires the escrow to already hold `stake_amount` per member
//!   (the member funds it with a native transfer before registering — ADR-011).
//!   Pre-states: `[state, escrow]`.
//! - `Slash` revokes the member and pays `stake_amount` out of the escrow to
//!   the slasher. The registry owns the escrow, so it debits it directly
//!   (rule 5). Pre-states: `[state, escrow, slasher]`.
//!
//! Hashing: SHA-256 with domain separators (ADR-005). All real logic lives in
//! `membership_registry_core` so host tests exercise the same code path.

#![no_main]

extern crate alloc;

use bincode::Options;
use membership_registry_core::{
    empty_tree_root, simulate_register, slash::verify_slash, staking, Commitment, ForumConfig,
    ForumState, Instruction, MerklePath, ModerationCertificateWire,
};
use nssa_core::{
    account::{AccountId, AccountWithMetadata, Data},
    program::{read_nssa_inputs, AccountPostState, Claim, PdaSeed, ProgramId, ProgramOutput},
};

risc0_zkvm::guest::entry!(main);

fn encode_state(state: &ForumState) -> alloc::vec::Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(state)
        .expect("ForumState encoding must succeed")
}

fn decode_state(bytes: &[u8]) -> ForumState {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(bytes)
        .expect("ForumState data must decode")
}

/// The escrow account's PDA, derived from this program + the state account id.
fn escrow_account_id(program_id: &ProgramId, state_id: &AccountId) -> ([u8; 32], AccountId) {
    let seed = staking::escrow_seed(state_id.value());
    (seed, AccountId::for_public_pda(program_id, &PdaSeed::new(seed)))
}

fn handle_initialize(
    program_id: ProgramId,
    state_pre: AccountWithMetadata,
    escrow_pre: AccountWithMetadata,
    config: ForumConfig,
    seed: [u8; 32],
) -> alloc::vec::Vec<AccountPostState> {
    let mut state_account = state_pre.account.clone();
    let state = ForumState {
        tree_root: empty_tree_root(),
        next_leaf_index: 0,
        revocation_set: alloc::vec::Vec::new(),
        revoked_secrets: alloc::vec::Vec::new(),
        config,
    };
    state_account.data = Data::try_from(encode_state(&state)).expect("ForumState fits Data limit");

    // Claim the escrow PDA so the registry owns it (enables the direct debit
    // on slash). It starts empty; members fund it before registering.
    let (escrow_seed, _escrow_id) = escrow_account_id(&program_id, &state_pre.account_id);

    alloc::vec![
        AccountPostState::new_claimed_if_default(state_account, Claim::Pda(PdaSeed::new(seed))),
        AccountPostState::new_claimed_if_default(
            escrow_pre.account.clone(),
            Claim::Pda(PdaSeed::new(escrow_seed)),
        ),
    ]
}

fn handle_register(
    program_id: ProgramId,
    state_pre: AccountWithMetadata,
    escrow_pre: AccountWithMetadata,
    commitment: Commitment,
    path_before: MerklePath,
    leaf_index: u32,
) -> alloc::vec::Vec<AccountPostState> {
    let mut state_account = state_pre.account.clone();
    let state = decode_state(state_account.data.as_ref());

    // The escrow must be the program's escrow PDA — reject a substituted one.
    let (_seed, escrow_id) = escrow_account_id(&program_id, &state_pre.account_id);
    assert!(escrow_pre.account_id == escrow_id, "wrong escrow account");

    // The escrow must hold stake for every member, including this one.
    let members_after = leaf_index as u128 + 1;
    let required = state
        .config
        .stake_amount
        .checked_mul(members_after)
        .expect("stake overflow");
    assert!(
        escrow_pre.account.balance >= required,
        "escrow underfunded: member must stake before registering"
    );

    let next = simulate_register(&state, commitment, &path_before, leaf_index)
        .unwrap_or_else(|e| panic!("register rejected: {e}"));
    state_account.data = Data::try_from(encode_state(&next)).expect("ForumState fits Data limit");

    alloc::vec![
        AccountPostState::new(state_account),
        AccountPostState::new(escrow_pre.account), // unchanged
    ]
}

fn handle_slash(
    program_id: ProgramId,
    state_pre: AccountWithMetadata,
    escrow_pre: AccountWithMetadata,
    slasher_pre: AccountWithMetadata,
    secret: [u8; 32],
    certificates: alloc::vec::Vec<ModerationCertificateWire>,
    leaf_index: u32,
    merkle_path: MerklePath,
) -> alloc::vec::Vec<AccountPostState> {
    let mut state_account = state_pre.account.clone();
    let mut state = decode_state(state_account.data.as_ref());

    let (_seed, escrow_id) = escrow_account_id(&program_id, &state_pre.account_id);
    assert!(escrow_pre.account_id == escrow_id, "wrong escrow account");

    let commitment = verify_slash(
        &secret,
        &certificates,
        &state.config,
        state.tree_root,
        leaf_index,
        &merkle_path,
        &state.revocation_set,
    )
    .unwrap_or_else(|e| panic!("slash rejected: {e:?}"));

    state.revocation_set.push(commitment);
    // Publish the reconstructed secret so verifiers reject this member's
    // future anonymous posts in any epoch (post_proof_core::is_revoked_post).
    state.revoked_secrets.push(secret);
    state_account.data = Data::try_from(encode_state(&state)).expect("ForumState fits Data limit");

    // Pay the stake out of the registry-owned escrow to the slasher. The
    // registry owns the escrow, so decreasing its balance is allowed (rule 5);
    // crediting the slasher is always allowed; total balance is preserved.
    let stake = state.config.stake_amount;
    let mut escrow_account = escrow_pre.account;
    let mut slasher_account = slasher_pre.account;
    escrow_account.balance = escrow_account
        .balance
        .checked_sub(stake)
        .expect("escrow cannot cover the stake claim");
    slasher_account.balance = slasher_account
        .balance
        .checked_add(stake)
        .expect("slasher balance overflow");

    alloc::vec![
        AccountPostState::new(state_account),
        AccountPostState::new(escrow_account),
        AccountPostState::new(slasher_account),
    ]
}

fn main() {
    let (input, instruction_data) = read_nssa_inputs::<Instruction>();
    let program_id = input.self_program_id;

    let get = |i: usize| {
        input
            .pre_states
            .get(i)
            .cloned()
            .unwrap_or_else(|| panic!("missing pre-state account #{i}"))
    };

    let post_states = match input.instruction {
        Instruction::Initialize { config, seed } => {
            handle_initialize(program_id, get(0), get(1), config, seed)
        }
        Instruction::Register {
            commitment,
            path_before,
            leaf_index,
        } => handle_register(program_id, get(0), get(1), commitment, path_before, leaf_index),
        Instruction::Slash {
            reconstructed_secret,
            certificates,
            leaf_index,
            merkle_path,
        } => handle_slash(
            program_id,
            get(0),
            get(1),
            get(2),
            reconstructed_secret,
            certificates,
            leaf_index,
            merkle_path,
        ),
    };

    ProgramOutput::new(
        program_id,
        input.caller_program_id,
        instruction_data,
        input.pre_states,
        post_states,
    )
    .write();
}
