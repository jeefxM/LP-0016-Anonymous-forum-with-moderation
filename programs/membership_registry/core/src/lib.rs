//! Shared types for the `membership_registry` LEZ program.
//!
//! These types live in a `no_std`-friendly crate so both the on-chain guest
//! and off-chain host helpers can import them without pulling in
//! `risc0-zkvm` or other heavy guest-only dependencies.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Depth of the membership Merkle tree. 2^16 = 65 536 members per forum
/// instance. Locked in P1.3; revisit before P9 if needed.
pub const TREE_DEPTH: usize = 16;
pub const MAX_LEAVES: u32 = 1 << TREE_DEPTH;

pub type Commitment = [u8; 32];
pub type Hash = [u8; 32];
/// Caller-supplied authenticated path from a leaf to the root.
pub type MerklePath = [Hash; TREE_DEPTH];
/// Ed25519 public key. We use raw 32-byte form; conversion to/from
/// `ed25519-dalek::VerifyingKey` happens in the host.
pub type ModeratorPubKey = [u8; 32];
/// Ed25519 signature. Wrapped so serde can derive Serialize/Deserialize on
/// the 64-byte array (serde's built-in impls only cover [T; N] for N ≤ 32).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeratorSig(#[serde(with = "serde_big_array::BigArray")] pub [u8; 64]);

impl From<[u8; 64]> for ModeratorSig {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

/// Top-level instruction enum. The on-chain program dispatches on this.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Instruction {
    /// First-time forum-instance setup. Initialises the `ForumState`
    /// account with the configured parameters. Only succeeds against
    /// an uninitialised PDA.
    ///
    /// `seed` is the 32-byte PDA seed the program claims under. The
    /// runner is responsible for deriving the same seed when computing
    /// the target `AccountId` for the transaction.
    Initialize {
        config: ForumConfig,
        seed: [u8; 32],
    },

    /// Register a new member commitment. Caller supplies the empty-leaf
    /// path so the guest can verify against the current `tree_root` and
    /// then compute the new root with `commitment` substituted in.
    Register {
        commitment: Commitment,
        /// Sibling hashes from the empty leaf up to the root. Pre-image
        /// for verification.
        path_before: MerklePath,
        /// Index of the leaf being inserted. Must equal
        /// `state.next_leaf_index`.
        leaf_index: u32,
    },

    /// Slash a member who has accumulated K moderation certificates.
    /// P2 ships this as a stub that panics; real verification lands in P5.
    Slash {
        commitment: Commitment,
        /// Reconstructed nullifier secret. Verified against the
        /// commitment in P5.
        reconstructed_secret: [u8; 32],
        /// Accumulated certificates (≥ K). Verified in P5.
        certificates: Vec<ModerationCertificateWire>,
    },
}

/// Per-instance configuration. Set once at `Initialize` and immutable
/// thereafter for v1.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForumConfig {
    /// Number of certificates required before slash is allowed.
    pub k_threshold: u8,
    /// Number of moderator signatures required per certificate.
    pub n_threshold: u8,
    /// The M moderator public keys. Length is M.
    pub moderators: Vec<ModeratorPubKey>,
    /// Stake in native units per registration.
    pub stake_amount: u128,
}

/// Persisted forum-instance state. Stored in the registry PDA's
/// `account.data`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForumState {
    /// Root of the membership Merkle tree.
    pub tree_root: Hash,
    /// Next free leaf index. Equal to current member count for as long as
    /// no leaves are reclaimed (we don't reclaim on slash — revocation is
    /// tracked separately).
    pub next_leaf_index: u32,
    /// Commitments that have been slashed. Posts whose proof points at one
    /// of these commitments are rejected client-side. Stored as a flat
    /// vector for v1; a Merkle root or Bloom filter is a v2 optimisation.
    pub revocation_set: Vec<Commitment>,
    /// Immutable per-instance configuration.
    pub config: ForumConfig,
}

impl ForumState {
    /// All-zero root for an empty depth-`TREE_DEPTH` tree. The guest
    /// recomputes this from the implicit empty-leaf and verifies on every
    /// register.
    pub const fn empty_root() -> Hash {
        // Computed off-chain and pinned. Recovered by walking up the tree
        // with leaf = [0; 32] and sibling = [0; 32] at every level using
        // the same `H("node", l, r)` rule the guest uses.
        // The actual constant is filled in once the guest's hash helper
        // is finalised; tests assert this matches.
        [0u8; 32]
    }
}

/// Wire format for a moderation certificate as it crosses the LEZ
/// instruction boundary. The off-chain library (`crates/moderation-cert`)
/// owns the richer in-memory form; this is the minimum the slash verifier
/// needs in P5.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModerationCertificateWire {
    /// Hash of the moderated content. Forum-app-defined.
    pub content_id: Hash,
    /// Index of the strike (0..K). Each member's K certificates must
    /// have distinct indices.
    pub strike_index: u8,
    /// Moderator signatures over `H(content_id || strike_index)`.
    /// Must contain ≥ N entries with distinct, valid moderator keys.
    pub signatures: Vec<(ModeratorPubKey, ModeratorSig)>,
}

/// Domain separators used by the program's hashing. Exposed publicly so
/// the host runner produces identical inputs.
pub mod tags {
    pub const COMMIT: &[u8] = b"commit";
    pub const NODE: &[u8] = b"node";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_roundtrips() {
        let cfg = ForumConfig {
            k_threshold: 3,
            n_threshold: 2,
            moderators: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            stake_amount: 1_000,
        };
        let inst = Instruction::Initialize {
            config: cfg.clone(),
            seed: [9u8; 32],
        };
        let bytes = serde_json::to_vec(&inst).unwrap();
        let back: Instruction = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(inst, back);
    }

    #[test]
    fn register_roundtrips() {
        let inst = Instruction::Register {
            commitment: [7u8; 32],
            path_before: [[0u8; 32]; TREE_DEPTH],
            leaf_index: 0,
        };
        let bytes = serde_json::to_vec(&inst).unwrap();
        let back: Instruction = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(inst, back);
    }
}
