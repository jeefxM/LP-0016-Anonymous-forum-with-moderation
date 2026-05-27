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

#![no_main]

use bincode::Options;
use membership_registry_core::{
    tags, Commitment, ForumConfig, ForumState, Hash, Instruction, MerklePath, TREE_DEPTH,
};
use nssa_core::{
    account::{Account, AccountWithMetadata, Data},
    program::{read_nssa_inputs, AccountPostState, Claim, PdaSeed, ProgramOutput},
};
use risc0_zkvm::sha::{Impl, Sha256};

risc0_zkvm::guest::entry!(main);

fn sha256_concat(parts: &[&[u8]]) -> Hash {
    let mut buf = alloc::vec::Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    let digest = Impl::hash_bytes(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

extern crate alloc;

fn leaf_hash(commitment: &Commitment) -> Hash {
    sha256_concat(&[tags::COMMIT, commitment])
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256_concat(&[tags::NODE, left, right])
}

/// Folds a leaf up the tree using `path`. `index` selects sibling
/// orientation per level (bit 0 = current is left child).
fn fold_path(leaf: Hash, path: &MerklePath, index: u32) -> Hash {
    let mut cur = leaf;
    for level in 0..TREE_DEPTH {
        let sibling = &path[level];
        let bit = (index >> level) & 1;
        cur = if bit == 0 {
            node_hash(&cur, sibling)
        } else {
            node_hash(sibling, &cur)
        };
    }
    cur
}

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

    // Compute the empty-tree root by folding a zero leaf with zero siblings.
    let empty_root = fold_path([0u8; 32], &[[0u8; 32]; TREE_DEPTH], 0);
    let state = ForumState {
        tree_root: empty_root,
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
    let mut state = decode_state(account.data.as_ref());

    assert_eq!(
        leaf_index, state.next_leaf_index,
        "leaf_index must equal next_leaf_index"
    );
    assert!(leaf_index < (1u32 << TREE_DEPTH), "registry is full");

    // 1. Verify the empty-leaf path matches the current root.
    let zero_leaf: Hash = [0u8; 32];
    let recomputed_before = fold_path(zero_leaf, &path_before, leaf_index);
    assert_eq!(
        recomputed_before, state.tree_root,
        "supplied path does not match current tree_root"
    );

    // 2. Replace zero with commitment and fold to get new root.
    let new_leaf = leaf_hash(&commitment);
    let new_root = fold_path(new_leaf, &path_before, leaf_index);

    state.tree_root = new_root;
    state.next_leaf_index = leaf_index + 1;

    let bytes = encode_state(&state);
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
