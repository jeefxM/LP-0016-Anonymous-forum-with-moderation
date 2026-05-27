//! LEZ program: per-forum membership registry.
//!
//! Implements `Initialize` and `Register` end-to-end. `Slash` is a stub
//! that panics — real verification lands in P5. The instruction shape is
//! finalised here so the off-chain SDK can build slash transactions now.
//!
//! Account model
//! =============
//! A single account per forum instance holds `ForumState`. The program
//! claims this account on `Initialize` via a PDA seeded by the forum id
//! (the caller supplies the seed). All subsequent instructions reference
//! the same account.
//!
//! Hashing
//! =======
//! SHA-256 with domain separators (matches `programs/post_proof` —
//! ADR-005). `H_leaf(c) = SHA256("commit" || c)`,
//! `H_node(l, r) = SHA256("node" || l || r)`.

//! Thin wrapper around `membership_registry_core`. All real logic
//! (Merkle folds, state encoding, register validity checks) lives in the
//! `core` crate so host tests exercise the exact same code path.

#![no_main]

extern crate alloc;

use bincode::Options;
use membership_registry_core::{
    empty_tree_root, simulate_register, Commitment, ForumConfig, ForumState, Instruction,
    MerklePath,
};
use nssa_core::{
    account::{AccountWithMetadata, Data},
    program::{read_nssa_inputs, AccountPostState, Claim, PdaSeed, ProgramOutput},
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

fn handle_initialize(
    pre_state: AccountWithMetadata,
    config: ForumConfig,
    seed: [u8; 32],
) -> alloc::vec::Vec<AccountPostState> {
    let mut account = pre_state.account.clone();
    let state = ForumState {
        tree_root: empty_tree_root(),
        next_leaf_index: 0,
        revocation_set: alloc::vec::Vec::new(),
        config,
    };
    let bytes = encode_state(&state);
    account.data = Data::try_from(bytes).expect("ForumState fits within Data limit");

    alloc::vec![AccountPostState::new_claimed_if_default(
        account,
        Claim::Pda(PdaSeed::new(seed)),
    )]
}

fn handle_register(
    pre_state: AccountWithMetadata,
    commitment: Commitment,
    path_before: MerklePath,
    leaf_index: u32,
) -> alloc::vec::Vec<AccountPostState> {
    let mut account = pre_state.account.clone();
    let state = decode_state(account.data.as_ref());

    let next = simulate_register(&state, commitment, &path_before, leaf_index)
        .unwrap_or_else(|e| panic!("register rejected: {e}"));

    let bytes = encode_state(&next);
    account.data = Data::try_from(bytes).expect("ForumState fits within Data limit");

    alloc::vec![AccountPostState::new(account)]
}

fn handle_slash_stub(_commitment: Commitment) -> alloc::vec::Vec<AccountPostState> {
    panic!("P5: slash verification not yet implemented");
}

fn main() {
    let (input, instruction_data) =
        read_nssa_inputs::<Instruction>();

    // Every instruction operates on a single state account.
    let pre_state = input
        .pre_states
        .first()
        .cloned()
        .expect("expected exactly one pre-state account");

    let post_states = match input.instruction {
        Instruction::Initialize { config, seed } => {
            handle_initialize(pre_state, config, seed)
        }
        Instruction::Register {
            commitment,
            path_before,
            leaf_index,
        } => handle_register(pre_state, commitment, path_before, leaf_index),
        Instruction::Slash { commitment, .. } => handle_slash_stub(commitment),
    };

    ProgramOutput::new(
        input.self_program_id,
        input.caller_program_id,
        instruction_data,
        input.pre_states,
        post_states,
    )
    .write();
}
