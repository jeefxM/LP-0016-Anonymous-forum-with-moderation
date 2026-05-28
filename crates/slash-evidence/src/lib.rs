//! Aggregates ≥K moderation certificates for a single commitment and
//! reconstructs the member's identity secret via Shamir recovery, ready
//! to be submitted as the slash transaction's instruction payload.
//!
//! ## Inputs
//!
//! 1. K accumulated moderation certificates against the same alleged
//!    member. Each cert authenticates `(content_id, strike_index)`.
//! 2. The K post envelopes referenced by those certs — providing the
//!    `(share_x, share_y)` for each post.
//! 3. The configured moderator set + N threshold (for cert verification).
//! 4. The current `ForumState` (for verifying that the reconstructed
//!    commitment is in the tree and not already revoked).
//!
//! ## Output
//!
//! A `SlashPayload` ready to be wrapped in `Instruction::Slash` and
//! submitted on-chain. The payload includes the reconstructed secret,
//! the cert collection, and a Merkle proof that the resulting commitment
//! is in the tree.
//!
//! ## What this crate does NOT do
//!
//! - Submit the transaction. That's the `lez-runner` crate's job.
//! - Verify the share-y was actually emitted by the post_proof guest.
//!   Anyone can audit this off-chain by re-deriving the share from the
//!   post envelope's journal; the protocol spec (`docs/protocol.md`)
//!   explains the trust model.

use moderation_cert::CertError;
use post_proof_core::shamir::{self, Fr};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use membership_registry_core::{
    Commitment, Hash, MerklePath, ModerationCertificateWire, ModeratorPubKey, TREE_DEPTH,
};

/// Per-post envelope (the bits of a post the slasher needs). Conceptually
/// matches what the `post_proof` guest commits to its receipt journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostEnvelope {
    pub content_id: Hash,
    pub share_x: Fr,
    pub share_y: Fr,
}

/// Payload for the LEZ `Instruction::Slash`. The on-chain verifier checks
/// each field; see `docs/protocol.md` for the full check list.
#[derive(Clone, Debug)]
pub struct SlashPayload {
    /// The recovered identity secret (32 bytes, Fr-encoded little-endian).
    pub reconstructed_secret: [u8; 32],
    /// Implied commitment = `commitment_of(reconstructed_secret)`.
    pub commitment: Commitment,
    /// K certificates, each over a distinct `content_id`.
    pub certificates: Vec<ModerationCertificateWire>,
    /// Merkle path from `commitment`'s leaf to the registry's `tree_root`.
    pub leaf_index: u32,
    pub merkle_path: MerklePath,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SlashError {
    #[error("not enough evidence: need {k} certs, got {got}")]
    BelowKThreshold { k: u8, got: usize },
    #[error("duplicate content_id across certificates")]
    DuplicateContent,
    #[error("certificate {idx}: {err}")]
    CertVerification { idx: usize, err: CertError },
    #[error("shamir reconstruction failed: {0}")]
    Reconstruction(&'static str),
    #[error("reconstructed commitment is already in the revocation set")]
    AlreadyRevoked,
    #[error("supplied Merkle path does not match the registry's tree_root")]
    BadCommitmentProof,
}

/// `commitment_of(secret) = sha256("commit" || secret)`. Identical to the
/// hash used by the post_proof guest and the membership_registry guest.
pub fn commitment_of(secret: &[u8; 32]) -> Commitment {
    let mut h = Sha256::new();
    h.update(b"commit");
    h.update(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}

/// Aggregate ≥ K certs (each carrying a signed Shamir share) into a
/// complete slash payload ready for submission. The payload is rejected
/// on-chain unless every field checks out.
///
/// Because the share is now bound into and signed within each cert
/// (ADR-008), the caller no longer supplies separate post envelopes — the
/// shares come straight from the certs.
/// Verify ≥K share-bound certs and reconstruct the member's identity secret
/// + commitment via Shamir Lagrange. Does NOT check the Merkle path or
/// revocation set — that's [`build_slash_payload`]. Used by the daemon's
/// `/v1/slash/recover` so a slasher can learn the commitment (and thus the
/// member's leaf) before assembling the full evidence (ADR-009).
pub fn recover_commitment(
    certs: &[ModerationCertificateWire],
    moderators: &[ModeratorPubKey],
    n_threshold: u8,
    k_threshold: u8,
) -> Result<([u8; 32], Commitment), SlashError> {
    if (certs.len() as u8) < k_threshold {
        return Err(SlashError::BelowKThreshold {
            k: k_threshold,
            got: certs.len(),
        });
    }

    // 1. Each cert must verify on its own (≥N valid moderator sigs over the
    //    content_id, strike_index, and bound share).
    for (idx, cert) in certs.iter().enumerate() {
        moderation_cert::verify(cert, moderators, n_threshold)
            .map_err(|err| SlashError::CertVerification { idx, err })?;
    }

    // 2. content_id collisions across certs would feed duplicate x values
    //    into Lagrange and degrade to non-recoverable.
    for i in 0..certs.len() {
        for j in 0..i {
            if certs[i].content_id == certs[j].content_id {
                return Err(SlashError::DuplicateContent);
            }
        }
    }

    // 3. Reconstruct the identity secret via Lagrange over the certs' shares.
    let points: Vec<(Fr, Fr)> = certs
        .iter()
        .map(|c| {
            (
                shamir::fr_from_bytes(&c.share_x),
                shamir::fr_from_bytes(&c.share_y),
            )
        })
        .collect();
    let reconstructed_secret =
        shamir::reconstruct_secret(&points).map_err(SlashError::Reconstruction)?;
    let commitment = commitment_of(&reconstructed_secret);
    Ok((reconstructed_secret, commitment))
}

pub fn build_slash_payload(
    certs: &[ModerationCertificateWire],
    moderators: &[ModeratorPubKey],
    n_threshold: u8,
    k_threshold: u8,
    tree_root: Hash,
    leaf_index: u32,
    merkle_path: MerklePath,
    revocation_set: &[Commitment],
) -> Result<SlashPayload, SlashError> {
    // Verify certs + reconstruct the secret/commitment (steps 1–3).
    let (reconstructed_secret, commitment) =
        recover_commitment(certs, moderators, n_threshold, k_threshold)?;

    // 4. Verify the reconstructed commitment is in the tree.
    if revocation_set.iter().any(|r| r == &commitment) {
        return Err(SlashError::AlreadyRevoked);
    }
    // Use commitment directly as the leaf — matches post_proof and the
    // updated membership_registry conventions. No extra leaf_hash here.
    let recomputed_root = fold_path(&commitment, &merkle_path, leaf_index);
    if recomputed_root != tree_root {
        return Err(SlashError::BadCommitmentProof);
    }

    Ok(SlashPayload {
        reconstructed_secret,
        commitment,
        certificates: certs.to_vec(),
        leaf_index,
        merkle_path,
    })
}

/// Same `fold_path` as `membership_registry_core` — folds a leaf up the
/// tree using sibling hashes and the index's bit pattern.
fn fold_path(leaf: &Hash, path: &MerklePath, index: u32) -> Hash {
    let mut cur = *leaf;
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

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(b"node");
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}

/// Off-chain post-proof verifier used after slash. A forum app calls this
/// before rendering a post to skip messages from revoked members. Today's
/// "revoked" check is just set membership; future versions could verify a
/// ZK non-membership proof.
pub fn is_member_revoked(commitment: &Commitment, revocation_set: &[Commitment]) -> bool {
    revocation_set.iter().any(|r| r == commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use membership_registry_core::ForumConfig;
    use moderation_cert::sign_vote;
    use post_proof_core::shamir::compute_share;
    use rand::rngs::OsRng;

    /// Build a fresh forum instance with a known secret and K=3 polynomial,
    /// plus a real Merkle tree with the member at leaf 0.
    struct TestSetup {
        secret: [u8; 32],
        commitment: Commitment,
        tree_root: Hash,
        leaf_path: MerklePath,
        mod_secrets: Vec<SigningKey>,
        mod_pubs: Vec<ModeratorPubKey>,
        n_threshold: u8,
        k_threshold: u8,
    }

    fn setup(k: u8, m: usize, n: u8) -> TestSetup {
        // Canonical Fr-encoded secret. Any 32-byte value that fits below
        // the BN254 Fr modulus (~254 bits) round-trips through
        // secret_to_fr → fr_to_bytes unchanged. Using a small non-trivial
        // pattern keeps the test reproducible.
        let mut secret = [0u8; 32];
        secret[0..16].copy_from_slice(&[0xAFu8; 16]);
        let commitment = commitment_of(&secret);
        // Singleton tree with our member at leaf 0, all-zero siblings.
        // Commitment IS the leaf (no extra leaf_hash) — matches the
        // post_proof guest's check.
        let mut cur = commitment;
        let leaf_path: MerklePath = [[0u8; 32]; TREE_DEPTH];
        for level in 0..TREE_DEPTH {
            cur = node_hash(&cur, &leaf_path[level]);
        }
        let tree_root = cur;

        let mut rng = OsRng;
        let mut mod_secrets = Vec::with_capacity(m);
        let mut mod_pubs = Vec::with_capacity(m);
        for _ in 0..m {
            let sk = SigningKey::generate(&mut rng);
            mod_pubs.push(sk.verifying_key().to_bytes());
            mod_secrets.push(sk);
        }

        TestSetup {
            secret,
            commitment,
            tree_root,
            leaf_path,
            mod_secrets,
            mod_pubs,
            n_threshold: n,
            k_threshold: k,
        }
    }

    /// Build a cert whose bound share is the member's real post-proof share
    /// for `content_id`. This mirrors what a moderator does: read the share
    /// off the flagged post envelope, then sign over it.
    fn build_cert(
        setup: &TestSetup,
        content_id: Hash,
        strike_index: u8,
    ) -> ModerationCertificateWire {
        let (x_fr, y_fr) = compute_share(&setup.secret, setup.k_threshold as usize, &content_id);
        let share_x = shamir::fr_to_bytes(&x_fr);
        let share_y = shamir::fr_to_bytes(&y_fr);
        let votes: Vec<_> = setup
            .mod_secrets
            .iter()
            .take(setup.n_threshold as usize)
            .map(|sk| sign_vote(sk, content_id, strike_index, share_x, share_y))
            .collect();
        moderation_cert::aggregate(&votes, setup.n_threshold).unwrap()
    }

    /// `strike_accumulation` — bounty-named test.
    /// Three certs against the same member, each from a different post.
    /// Aggregation succeeds and the reconstructed commitment matches.
    #[test]
    fn strike_accumulation() {
        let s = setup(3, 5, 3);
        let cids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| build_cert(&s, *cid, i as u8))
            .collect();

        let payload = build_slash_payload(
            &certs,
            &s.mod_pubs,
            s.n_threshold,
            s.k_threshold,
            s.tree_root,
            0,
            s.leaf_path,
            &[],
        )
        .expect("3 valid strikes must aggregate into a slash payload");

        assert_eq!(payload.commitment, s.commitment);
        assert_eq!(payload.certificates.len(), 3);
    }

    /// `slash_submission` — bounty-named test.
    /// Full slash payload verifies end-to-end including the Merkle
    /// commitment-in-tree check.
    #[test]
    fn slash_submission() {
        let s = setup(3, 5, 3);
        let cids = [[10u8; 32], [20u8; 32], [30u8; 32]];
        let certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| build_cert(&s, *cid, i as u8))
            .collect();

        let payload = build_slash_payload(
            &certs,
            &s.mod_pubs,
            s.n_threshold,
            s.k_threshold,
            s.tree_root,
            0,
            s.leaf_path,
            &[],
        )
        .expect("slash submission must succeed");

        // The reconstructed secret must round-trip through commitment_of
        // back to the on-chain commitment.
        assert_eq!(commitment_of(&payload.reconstructed_secret), s.commitment);
    }

    /// `post_rejection_after_revocation` — bounty-named test.
    /// After slash, a fresh post by the same member is rejected because
    /// the commitment is in the revocation set.
    #[test]
    fn post_rejection_after_revocation() {
        let s = setup(3, 5, 3);
        // First, slash:
        let cids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| build_cert(&s, *cid, i as u8))
            .collect();
        let payload = build_slash_payload(
            &certs,
            &s.mod_pubs,
            s.n_threshold,
            s.k_threshold,
            s.tree_root,
            0,
            s.leaf_path,
            &[],
        )
        .unwrap();

        // Simulate the registry adding the commitment to the revocation set.
        let revocation_set = vec![payload.commitment];

        // A fresh post by the same member's commitment is now rejected.
        assert!(is_member_revoked(&payload.commitment, &revocation_set));

        // And the slasher can't re-slash a revoked member either.
        let err = build_slash_payload(
            &certs,
            &s.mod_pubs,
            s.n_threshold,
            s.k_threshold,
            s.tree_root,
            0,
            s.leaf_path,
            &revocation_set,
        )
        .unwrap_err();
        assert_eq!(err, SlashError::AlreadyRevoked);
    }

    /// The vendored shamir copy in membership_registry_core must produce
    /// byte-identical shares to the original in post_proof_core. Guards
    /// against the two copies drifting (see the vendored-copy note in
    /// membership_registry_core::shamir).
    #[test]
    fn vendored_shamir_matches_original() {
        use membership_registry_core::shamir as vendored;
        use post_proof_core::shamir as original;
        let secret = {
            let mut s = [0u8; 32];
            s[0..16].copy_from_slice(&[0x5Cu8; 16]);
            s
        };
        for k in 1..=5usize {
            let oc = original::polynomial_coefficients(&secret, k);
            let vc = vendored::polynomial_coefficients(&secret, k);
            assert_eq!(oc, vc, "coeffs differ at k={k}");
            for cid_byte in [0u8, 1, 7, 200] {
                let cid = [cid_byte; 32];
                let (ox, oy) = original::compute_share(&secret, k, &cid);
                let (vx, vy) = (
                    vendored::derive_share_x(&secret, &cid),
                    vendored::poly_eval(&vc, vendored::derive_share_x(&secret, &cid)),
                );
                assert_eq!(ox, vx, "share_x differ k={k} cid={cid_byte}");
                assert_eq!(oy, vy, "share_y differ k={k} cid={cid_byte}");
            }
        }
    }

    /// Full cross-system coherence: the share that the `post_proof` guest
    /// commits in its Journal is exactly the share `verify_slash` accepts.
    /// This is the seam between the two guests — if their share math ever
    /// diverged, a real post couldn't be slashed. We drive it through
    /// `prove_post` (not `compute_share`) to exercise the actual guest path.
    #[test]
    fn post_proof_share_satisfies_verify_slash() {
        use membership_registry_core::slash::verify_slash;
        use post_proof_core::{build_singleton_tree, prove_post, PrivateInputs, PublicInputs};

        let s = setup(3, 5, 3);
        let config = ForumConfig {
            k_threshold: s.k_threshold,
            n_threshold: s.n_threshold,
            moderators: s.mod_pubs.clone(),
            stake_amount: 1_000,
        };
        // Member at leaf 0 of a singleton tree.
        let (tree_root, siblings) = build_singleton_tree(&s.secret);

        let cids = [[71u8; 32], [72u8; 32], [73u8; 32]];
        let certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| {
                // Run the actual post-proof construction to get the share.
                let journal = prove_post(
                    &PrivateInputs {
                        secret: s.secret,
                        merkle_siblings: siblings,
                        merkle_path_bits: 0,
                    },
                    &PublicInputs {
                        tree_root,
                        epoch: 1,
                        content_id: *cid,
                        k_threshold: s.k_threshold as u32,
                    },
                )
                .expect("post proof");
                // Moderators sign over the guest-emitted share.
                let votes: Vec<_> = s
                    .mod_secrets
                    .iter()
                    .take(s.n_threshold as usize)
                    .map(|sk| sign_vote(sk, *cid, i as u8, journal.share_x, journal.share_y))
                    .collect();
                moderation_cert::aggregate(&votes, s.n_threshold).unwrap()
            })
            .collect();

        // The tree built by build_singleton_tree must match what the registry
        // would hold; verify_slash uses commitment-as-leaf with the same path.
        let commitment = verify_slash(&s.secret, &certs, &config, tree_root, 0, &siblings, &[])
            .expect("guest-emitted shares must satisfy on-chain verify_slash");
        assert_eq!(commitment, commitment_of(&s.secret));
    }

    /// On-chain verify_slash accepts a correctly-reconstructed secret with
    /// K valid share-bound certs.
    #[test]
    fn verify_slash_happy_path() {
        use membership_registry_core::slash::verify_slash;
        let s = setup(3, 5, 3);
        let config = ForumConfig {
            k_threshold: s.k_threshold,
            n_threshold: s.n_threshold,
            moderators: s.mod_pubs.clone(),
            stake_amount: 1_000,
        };
        let cids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| build_cert(&s, *cid, i as u8))
            .collect();

        let commitment = verify_slash(
            &s.secret,
            &certs,
            &config,
            s.tree_root,
            0,
            &s.leaf_path,
            &[],
        )
        .expect("valid slash must verify on-chain");
        assert_eq!(commitment, s.commitment);
    }

    /// A forged secret (not the one that produced the shares) is rejected
    /// at the share_x binding check — this is the ADR-008 guarantee.
    #[test]
    fn verify_slash_rejects_forged_secret() {
        use membership_registry_core::slash::{verify_slash, SlashVerifyError};
        let s = setup(3, 5, 3);
        let config = ForumConfig {
            k_threshold: s.k_threshold,
            n_threshold: s.n_threshold,
            moderators: s.mod_pubs.clone(),
            stake_amount: 1_000,
        };
        // Certs carry shares from member A (s.secret).
        let cids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| build_cert(&s, *cid, i as u8))
            .collect();

        // Attacker submits a DIFFERENT secret with A's certs.
        let mut forged = [0u8; 32];
        forged[0..16].copy_from_slice(&[0x11u8; 16]);
        let err =
            verify_slash(&forged, &certs, &config, s.tree_root, 0, &s.leaf_path, &[]).unwrap_err();
        assert_eq!(err, SlashVerifyError::ShareXMismatch { idx: 0 });
    }

    /// A cert with fewer than N signatures is rejected.
    #[test]
    fn verify_slash_rejects_below_n() {
        use membership_registry_core::slash::{verify_slash, SlashVerifyError};
        let s = setup(3, 5, 3);
        let config = ForumConfig {
            k_threshold: s.k_threshold,
            n_threshold: s.n_threshold,
            moderators: s.mod_pubs.clone(),
            stake_amount: 1_000,
        };
        let cids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| build_cert(&s, *cid, i as u8))
            .collect();
        // Strip one signature from the first cert so it falls below N=3.
        certs[0].signatures.pop();
        let err = verify_slash(
            &s.secret,
            &certs,
            &config,
            s.tree_root,
            0,
            &s.leaf_path,
            &[],
        )
        .unwrap_err();
        assert_eq!(err, SlashVerifyError::CertBelowNThreshold { idx: 0 });
    }

    #[test]
    fn below_k_rejected() {
        let s = setup(3, 5, 3);
        let cids = [[1u8; 32], [2u8; 32]];
        let certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| build_cert(&s, *cid, i as u8))
            .collect();
        let err = build_slash_payload(
            &certs,
            &s.mod_pubs,
            s.n_threshold,
            s.k_threshold,
            s.tree_root,
            0,
            s.leaf_path,
            &[],
        )
        .unwrap_err();
        assert_eq!(err, SlashError::BelowKThreshold { k: 3, got: 2 });
    }

    #[test]
    fn wrong_tree_root_rejected() {
        let s = setup(3, 5, 3);
        let cids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let certs: Vec<_> = cids
            .iter()
            .enumerate()
            .map(|(i, cid)| build_cert(&s, *cid, i as u8))
            .collect();
        let bogus_root = [0xFFu8; 32];
        let err = build_slash_payload(
            &certs,
            &s.mod_pubs,
            s.n_threshold,
            s.k_threshold,
            bogus_root,
            0,
            s.leaf_path,
            &[],
        )
        .unwrap_err();
        assert_eq!(err, SlashError::BadCommitmentProof);
    }
}
