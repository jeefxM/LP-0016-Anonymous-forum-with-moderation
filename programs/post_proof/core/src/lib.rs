//! Shared logic for the `post_proof` RISC0 guest.
//!
//! The guest is a thin wrapper around `prove_post`: it reads the binary
//! inputs out of the zkVM environment, calls `prove_post`, and commits the
//! resulting `Journal` to the receipt. Host code uses the same functions to
//! pre-compute test inputs and to verify off-line that what the guest
//! claims matches what the construction says.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod shamir;

use core::convert::TryInto;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Tree depth. 2^16 = 65 536 members per forum instance.
pub const TREE_DEPTH: usize = 16;

pub type Hash = [u8; 32];
pub type Commitment = Hash;

/// Domain separators. Stay byte-identical with `membership_registry_core`
/// so a commitment placed in the registry verifies under both programs.
pub mod tags {
    pub const COMMIT: &[u8] = b"commit";
    pub const NODE: &[u8] = b"node";
    pub const NULL: &[u8] = b"null";
    pub const SHARE_X: &[u8] = b"x";
    pub const SHARE_Y: &[u8] = b"y";
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Journal {
    pub tree_root: Hash,
    pub epoch: u64,
    pub content_id: Hash,
    pub nullifier: Hash,
    pub share_x: Hash,
    pub share_y: Hash,
}

/// Total private-input size in bytes, used by the guest to size its
/// `read_slice` buffer. 32 (secret) + 16×32 (siblings) + 4 (path_bits) =
/// 548 bytes = 137 u32 words.
pub const PRIVATE_INPUTS_BYTES: usize = 32 + TREE_DEPTH * 32 + 4;
pub const PRIVATE_INPUTS_U32S: usize = PRIVATE_INPUTS_BYTES / 4;

/// Total public-input size in bytes. 32 (tree_root) + 8 (epoch) + 32
/// (content_id) + 4 (k_threshold) = 76 bytes = 19 u32 words.
pub const PUBLIC_INPUTS_BYTES: usize = 32 + 8 + 32 + 4;
pub const PUBLIC_INPUTS_U32S: usize = PUBLIC_INPUTS_BYTES / 4;

/// Encoded form sent to the guest as a contiguous byte slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateInputs {
    pub secret: Hash,
    pub merkle_siblings: [Hash; TREE_DEPTH],
    pub merkle_path_bits: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub tree_root: Hash,
    pub epoch: u64,
    pub content_id: Hash,
    /// Forum instance's K (revocation threshold). Sets the degree of the
    /// member's Shamir polynomial so K shares reconstruct the secret.
    pub k_threshold: u32,
}

impl PrivateInputs {
    pub fn to_bytes(&self) -> [u8; PRIVATE_INPUTS_BYTES] {
        let mut out = [0u8; PRIVATE_INPUTS_BYTES];
        let mut off = 0;
        out[off..off + 32].copy_from_slice(&self.secret);
        off += 32;
        for sib in &self.merkle_siblings {
            out[off..off + 32].copy_from_slice(sib);
            off += 32;
        }
        out[off..off + 4].copy_from_slice(&self.merkle_path_bits.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; PRIVATE_INPUTS_BYTES]) -> Self {
        let mut off = 0;
        let secret: Hash = bytes[off..off + 32].try_into().unwrap();
        off += 32;
        let mut merkle_siblings = [[0u8; 32]; TREE_DEPTH];
        for sib in &mut merkle_siblings {
            sib.copy_from_slice(&bytes[off..off + 32]);
            off += 32;
        }
        let merkle_path_bits = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        Self {
            secret,
            merkle_siblings,
            merkle_path_bits,
        }
    }
}

impl PublicInputs {
    pub fn to_bytes(&self) -> [u8; PUBLIC_INPUTS_BYTES] {
        let mut out = [0u8; PUBLIC_INPUTS_BYTES];
        out[0..32].copy_from_slice(&self.tree_root);
        out[32..40].copy_from_slice(&self.epoch.to_le_bytes());
        out[40..72].copy_from_slice(&self.content_id);
        out[72..76].copy_from_slice(&self.k_threshold.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; PUBLIC_INPUTS_BYTES]) -> Self {
        let mut tree_root = [0u8; 32];
        tree_root.copy_from_slice(&bytes[0..32]);
        let epoch = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let mut content_id = [0u8; 32];
        content_id.copy_from_slice(&bytes[40..72]);
        let k_threshold = u32::from_le_bytes(bytes[72..76].try_into().unwrap());
        Self {
            tree_root,
            epoch,
            content_id,
            k_threshold,
        }
    }
}

// ── Hashing ──────────────────────────────────────────────────────────

fn sha256_concat(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}

pub fn commitment_of(secret: &Hash) -> Commitment {
    sha256_concat(&[tags::COMMIT, secret])
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256_concat(&[tags::NODE, left, right])
}

// ── Construction ─────────────────────────────────────────────────────

/// Verifies the Merkle path and computes the post-proof outputs.
/// Returns `Err` on path mismatch (the guest panics on `Err` so the
/// receipt won't be generated).
pub fn prove_post(private: &PrivateInputs, public: &PublicInputs) -> Result<Journal, &'static str> {
    let priv_bytes = private.to_bytes();
    let pub_bytes = public.to_bytes();
    prove_post_from_bytes(&priv_bytes, &pub_bytes)
}

/// Same as `prove_post` but operates on raw byte slices. The guest calls
/// this directly to avoid materialising a `PrivateInputs` struct from the
/// read buffer — the byte-shuffle is the largest single contributor to
/// user-cycle count, so we keep it on the host where it doesn't matter.
pub fn prove_post_from_bytes(
    priv_bytes: &[u8; PRIVATE_INPUTS_BYTES],
    pub_bytes: &[u8; PUBLIC_INPUTS_BYTES],
) -> Result<Journal, &'static str> {
    // Slice in-place without copying. Layout:
    //   private[0..32]   = secret
    //   private[32..544] = siblings (16 × 32)
    //   private[544..548] = merkle_path_bits (u32 LE)
    //   public[0..32]    = tree_root
    //   public[32..40]   = epoch (u64 LE)
    //   public[40..72]   = content_id
    let secret: &[u8; 32] = priv_bytes[0..32].try_into().unwrap();
    let path_bits = u32::from_le_bytes(priv_bytes[544..548].try_into().unwrap());
    let tree_root: &[u8; 32] = pub_bytes[0..32].try_into().unwrap();
    let epoch_bytes: &[u8; 8] = pub_bytes[32..40].try_into().unwrap();
    let content_id: &[u8; 32] = pub_bytes[40..72].try_into().unwrap();
    let k_threshold = u32::from_le_bytes(pub_bytes[72..76].try_into().unwrap()) as usize;

    // 1. Membership: commitment of secret lies in the published tree.
    let commitment = commitment_of(secret);
    let mut cur = commitment;
    for level in 0..TREE_DEPTH {
        let sibling_start = 32 + level * 32;
        let sibling: &[u8; 32] = priv_bytes[sibling_start..sibling_start + 32]
            .try_into()
            .unwrap();
        let bit = (path_bits >> level) & 1;
        cur = if bit == 0 {
            node_hash(&cur, sibling)
        } else {
            node_hash(sibling, &cur)
        };
    }
    if &cur != tree_root {
        return Err("Merkle path does not match root");
    }

    // 2. Nullifier ties this post to (secret, epoch).
    let nullifier = compute_nullifier(secret, u64::from_le_bytes(*epoch_bytes));

    // 3. Real Shamir share over BN254 Fr. The member's degree-(K-1)
    //    polynomial is deterministic in (secret, K); share_x is unique per
    //    content_id. Collecting K shares (via K moderation certs)
    //    reconstructs the secret on slash. This is the share the
    //    membership_registry's verify_slash checks against — they MUST
    //    agree, which the vendored-shamir cross-check test enforces.
    let (x_fr, y_fr) = shamir::compute_share(secret, k_threshold, content_id);
    let share_x = shamir::fr_to_bytes(&x_fr);
    let share_y = shamir::fr_to_bytes(&y_fr);

    Ok(Journal {
        tree_root: *tree_root,
        epoch: u64::from_le_bytes(*epoch_bytes),
        content_id: *content_id,
        nullifier,
        share_x,
        share_y,
    })
}

// ── Nullifier + revocation enforcement ──────────────────────────────

/// A member's post nullifier: `H("null" || secret || epoch_LE)`. Identical
/// to the value committed by `prove_post` and emitted by the membership
/// circuit. Deterministic in `(secret, epoch)`: same epoch ⇒ same nullifier
/// (posts linkable within an epoch), different epochs ⇒ unlinkable.
pub fn compute_nullifier(secret: &Hash, epoch: u64) -> Hash {
    sha256_concat(&[tags::NULL, secret, &epoch.to_le_bytes()])
}

/// True if `nullifier_value` (from an anonymous post envelope at `epoch`)
/// belongs to any revoked member.
///
/// A post envelope carries a nullifier, not a commitment, so a revoked
/// member can't be matched by commitment. But once slashed, the member's
/// secret is reconstructed and published on-chain (`ForumState.revoked_secrets`),
/// so any verifier can recompute their nullifier for the post's (proven)
/// epoch and reject the post. This is the enforcement side of the
/// "retroactive deanonymization upon slash" property (docs/protocol.md).
pub fn is_revoked_post(revoked_secrets: &[Hash], epoch: u64, nullifier_value: &Hash) -> bool {
    revoked_secrets
        .iter()
        .any(|s| &compute_nullifier(s, epoch) == nullifier_value)
}

// ── Test helpers — used by both the host benchmark and unit tests ────

pub fn empty_path() -> [Hash; TREE_DEPTH] {
    [[0u8; 32]; TREE_DEPTH]
}

/// Build a complete tree where leaf 0 is `commitment_of(secret)` and all
/// other leaves are zero. Returns (tree_root, siblings_for_leaf_0).
pub fn build_singleton_tree(secret: &Hash) -> (Hash, [Hash; TREE_DEPTH]) {
    let commitment = commitment_of(secret);
    let siblings = empty_path();
    let mut cur = commitment;
    for level in 0..TREE_DEPTH {
        cur = node_hash(&cur, &siblings[level]);
    }
    (cur, siblings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_private_inputs() {
        let private = PrivateInputs {
            secret: [1u8; 32],
            merkle_siblings: [
                [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32],
                [8u8; 32], [9u8; 32], [10u8; 32], [11u8; 32], [12u8; 32], [13u8; 32],
                [14u8; 32], [15u8; 32], [16u8; 32], [17u8; 32],
            ],
            merkle_path_bits: 0xCAFE_BABE,
        };
        let bytes = private.to_bytes();
        let back = PrivateInputs::from_bytes(&bytes);
        assert_eq!(private, back);
    }

    #[test]
    fn roundtrip_public_inputs() {
        let public = PublicInputs {
            tree_root: [1u8; 32],
            epoch: 1_234_567,
            content_id: [42u8; 32],
            k_threshold: 3,
        };
        let bytes = public.to_bytes();
        let back = PublicInputs::from_bytes(&bytes);
        assert_eq!(public, back);
    }

    #[test]
    fn happy_path_proves() {
        let secret = [7u8; 32];
        let (root, siblings) = build_singleton_tree(&secret);
        let private = PrivateInputs {
            secret,
            merkle_siblings: siblings,
            merkle_path_bits: 0,
        };
        let public = PublicInputs {
            tree_root: root,
            epoch: 1,
            content_id: [42u8; 32],
            k_threshold: 3,
        };
        let journal = prove_post(&private, &public).expect("happy path should succeed");
        assert_eq!(journal.tree_root, root);
        assert_eq!(journal.epoch, 1);
        assert_ne!(journal.nullifier, [0u8; 32]);
        assert_ne!(journal.share_x, [0u8; 32]);
        assert_ne!(journal.share_y, [0u8; 32]);
    }

    #[test]
    fn rejects_tampered_path() {
        let secret = [7u8; 32];
        let (root, mut siblings) = build_singleton_tree(&secret);
        siblings[3] = [0xFFu8; 32]; // tamper with a sibling
        let private = PrivateInputs {
            secret,
            merkle_siblings: siblings,
            merkle_path_bits: 0,
        };
        let public = PublicInputs {
            tree_root: root,
            epoch: 1,
            content_id: [42u8; 32],
            k_threshold: 3,
        };
        assert!(prove_post(&private, &public).is_err());
    }

    #[test]
    fn rejects_wrong_secret() {
        let secret = [7u8; 32];
        let (root, siblings) = build_singleton_tree(&secret);
        let private = PrivateInputs {
            secret: [99u8; 32], // wrong
            merkle_siblings: siblings,
            merkle_path_bits: 0,
        };
        let public = PublicInputs {
            tree_root: root,
            epoch: 1,
            content_id: [42u8; 32],
            k_threshold: 3,
        };
        assert!(prove_post(&private, &public).is_err());
    }

    #[test]
    fn nullifier_changes_with_epoch_but_not_content() {
        let secret = [1u8; 32];
        let (root, siblings) = build_singleton_tree(&secret);
        let mk = |epoch: u64, content: [u8; 32]| -> Journal {
            prove_post(
                &PrivateInputs {
                    secret,
                    merkle_siblings: siblings,
                    merkle_path_bits: 0,
                },
                &PublicInputs {
                    tree_root: root,
                    epoch,
                    content_id: content,
            k_threshold: 3,
                },
            )
            .unwrap()
        };
        let a = mk(1, [1u8; 32]);
        let b = mk(1, [2u8; 32]);
        let c = mk(2, [1u8; 32]);
        // Same epoch → same nullifier regardless of content.
        assert_eq!(a.nullifier, b.nullifier);
        // Different epoch → different nullifier.
        assert_ne!(a.nullifier, c.nullifier);
        // Share_x depends on content (so two posts in the same epoch
        // generate distinct shares — that's the requirement for
        // share-reveal-via-K-certs to work).
        assert_ne!(a.share_x, b.share_x);
    }

    /// Anonymous-path revocation enforcement: once a member's secret is
    /// reconstructed on slash, their posts are rejectable in ANY epoch even
    /// though the envelope carries only a nullifier (no commitment).
    #[test]
    fn revoked_member_posts_rejected_across_epochs() {
        let secret = [1u8; 32];
        let other = [2u8; 32];
        let (root, siblings) = build_singleton_tree(&secret);
        let post = |epoch: u64| {
            prove_post(
                &PrivateInputs { secret, merkle_siblings: siblings, merkle_path_bits: 0 },
                &PublicInputs { tree_root: root, epoch, content_id: [9u8; 32], k_threshold: 3 },
            )
            .unwrap()
        };

        // The helper matches what prove_post commits (no drift).
        let j1 = post(1);
        assert_eq!(compute_nullifier(&secret, 1), j1.nullifier);

        let revoked = [secret];
        // The revoked member is caught in the epoch they were seen in...
        assert!(is_revoked_post(&revoked, 1, &j1.nullifier));
        // ...and in a fresh epoch they try to escape into.
        let j2 = post(2);
        assert!(is_revoked_post(&revoked, 2, &j2.nullifier));
        // A non-revoked member's post is not flagged.
        assert!(!is_revoked_post(&revoked, 1, &compute_nullifier(&other, 1)));
        // Epoch must match: the revoked nullifier for epoch 1 isn't matched at epoch 2.
        assert!(!is_revoked_post(&revoked, 2, &j1.nullifier));
    }
}
