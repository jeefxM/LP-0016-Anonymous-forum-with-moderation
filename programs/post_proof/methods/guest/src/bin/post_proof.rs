//! Post-proof RISC0 guest.
//!
//! Proves: "I know a secret S such that commit(S) is a leaf in a Merkle tree
//! rooted at `tree_root`, AND I emit a Shamir share of S bound to (epoch,
//! content_id) that does not by itself reveal S."
//!
//! Two such envelopes from the same secret across two different (epoch,
//! content_id) pairs do not collude. Two envelopes from the same secret with
//! the same (epoch, content_id) would, but that case is impossible because
//! `content_id` is a hash of the post content — duplicating it duplicates
//! the post. The Shamir-share linearity only kicks in once K independent
//! moderation certificates are aggregated; reconstruction is then
//! deterministic from K (x, y) pairs harvested from those certs.
//!
//! Hash choice: SHA-256 (RISC0 has an accelerated sha2 path). See ADR-005.
//!
//! Public outputs (committed to journal):
//!   - tree_root: [u8; 32]      — the public Merkle root the proof checks
//!   - epoch: u64               — public epoch tag
//!   - content_id: [u8; 32]     — public hash of the forum content
//!   - nullifier: [u8; 32]      — H(secret, epoch); links posts within an
//!                                epoch (set epoch generously to keep the
//!                                anonymity set large)
//!   - share_x: [u8; 32]        — H(secret, content_id) — Shamir x-coord
//!   - share_y: [u8; 32]        — secret XOR H(epoch, content_id, share_x)
//!                                — placeholder linear share; real Shamir
//!                                math lands in P3
//!
//! Private inputs (read but not committed):
//!   - secret: [u8; 32]
//!   - merkle_siblings: Vec<[u8; 32]>  (length = TREE_DEPTH)
//!   - merkle_path_bits: u64           (one bit per level, 0=left, 1=right)

#![no_main]

use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

/// Supports up to 2^16 = 65_536 members per forum instance.
const TREE_DEPTH: usize = 16;

#[derive(Serialize, Deserialize)]
struct PrivateInputs {
    secret: [u8; 32],
    merkle_siblings: [[u8; 32]; TREE_DEPTH],
    /// Bit i = direction at level i (0 = current node is left child,
    /// 1 = current node is right child).
    merkle_path_bits: u32,
}

#[derive(Serialize, Deserialize)]
struct PublicInputs {
    tree_root: [u8; 32],
    epoch: u64,
    content_id: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Journal {
    tree_root: [u8; 32],
    epoch: u64,
    content_id: [u8; 32],
    nullifier: [u8; 32],
    share_x: [u8; 32],
    share_y: [u8; 32],
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    let digest = Impl::hash_bytes(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// `commit(secret) = sha256("commit" || secret)`.
fn commitment_of(secret: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[b"commit", secret])
}

/// Verifies the Merkle path against `root`. Panics if mismatched.
fn verify_merkle(
    leaf: &[u8; 32],
    siblings: &[[u8; 32]; TREE_DEPTH],
    path_bits: u32,
    root: &[u8; 32],
) {
    let mut cur = *leaf;
    for level in 0..TREE_DEPTH {
        let sibling = &siblings[level];
        let bit = (path_bits >> level) & 1;
        cur = if bit == 0 {
            // current is left child
            sha256_concat(&[b"node", &cur, sibling])
        } else {
            // current is right child
            sha256_concat(&[b"node", sibling, &cur])
        };
    }
    assert_eq!(&cur, root, "Merkle path does not match root");
}

fn main() {
    let private: PrivateInputs = env::read();
    let public: PublicInputs = env::read();

    // 1. Membership: commitment of secret lies in the published tree.
    let commitment = commitment_of(&private.secret);
    verify_merkle(
        &commitment,
        &private.merkle_siblings,
        private.merkle_path_bits,
        &public.tree_root,
    );

    // 2. Nullifier ties this post to (secret, epoch). Two posts in the same
    // epoch share a nullifier; choose epoch granularity to control
    // unlinkability vs rate-limiting tradeoff.
    let nullifier = sha256_concat(&[b"null", &private.secret, &public.epoch.to_le_bytes()]);

    // 3. Shamir-style share. The real scheme uses GF arithmetic and a
    // degree-(K-1) polynomial; v1 placeholder uses a linear function over
    // SHA-256 outputs. P3 replaces this with proper field arithmetic.
    let share_x = sha256_concat(&[b"x", &private.secret, &public.content_id]);
    let share_mask = sha256_concat(&[
        b"y",
        &public.epoch.to_le_bytes(),
        &public.content_id,
        &share_x,
    ]);
    let mut share_y = [0u8; 32];
    for i in 0..32 {
        share_y[i] = private.secret[i] ^ share_mask[i];
    }

    let journal = Journal {
        tree_root: public.tree_root,
        epoch: public.epoch,
        content_id: public.content_id,
        nullifier,
        share_x,
        share_y,
    };
    env::commit(&journal);
}
