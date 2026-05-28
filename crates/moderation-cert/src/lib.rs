//! N-of-M moderation certificate library.
//!
//! Each moderator signs a strike independently with their own Ed25519 key.
//! When ≥ N distinct moderators have signed the same (content_id,
//! strike_index), the signatures can be aggregated into a single
//! `ModerationCertificateWire` ready for inclusion in a `Slash` LEZ
//! transaction.
//!
//! Threshold scheme is **naive ≥N independent signatures** — no FROST,
//! no BLS aggregation. The choice is recorded in ADR-003.
//!
//! ## Public API
//!
//! - [`sign_vote`] — one moderator signs one strike
//! - [`aggregate`] — bundle ≥ N independent votes into a cert
//! - [`verify`] — check a cert is well-formed and from registered moderators

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use membership_registry_core::{
    Hash, ModerationCertificateWire, ModeratorPubKey, ModeratorSig,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separator for the message bytes each moderator signs. Keeps
/// these signatures from being mis-applied to any other context.
pub const DOMAIN: &[u8] = b"forum-protocol/v1/modcert";

/// One moderator's signature over a (content_id, strike_index) pair.
/// Holds the public key so `aggregate` can verify uniqueness without
/// needing the caller to track ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub moderator_pub: ModeratorPubKey,
    pub content_id: Hash,
    pub strike_index: u8,
    pub signature: ModeratorSig,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertError {
    #[error("threshold N={n} not met: only {got} valid signatures")]
    BelowThreshold { n: u8, got: usize },
    #[error("votes disagree on content_id or strike_index")]
    InconsistentVotes,
    #[error("duplicate signer detected")]
    DuplicateSigner,
    #[error("signer is not in the configured moderator set")]
    UnknownSigner,
    #[error("invalid Ed25519 signature")]
    BadSignature,
    #[error("invalid Ed25519 public key encoding")]
    BadPubkey,
}

/// Bytes a moderator signs. Domain-separated SHA-256 over the cert's
/// canonical fields.
pub fn message_to_sign(content_id: &Hash, strike_index: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(content_id);
    h.update([strike_index]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}

/// Sign one vote. Used by moderator-side code in the SDK.
pub fn sign_vote(
    signing_key: &SigningKey,
    content_id: Hash,
    strike_index: u8,
) -> Vote {
    let msg = message_to_sign(&content_id, strike_index);
    let signature: Signature = signing_key.sign(&msg);
    Vote {
        moderator_pub: signing_key.verifying_key().to_bytes(),
        content_id,
        strike_index,
        signature: ModeratorSig(signature.to_bytes()),
    }
}

/// Aggregate votes into a wire certificate. Caller passes the configured
/// `n_threshold` so we can fail-fast if not enough independent moderators
/// have signed. Caller must ensure every vote is for the same
/// (content_id, strike_index).
pub fn aggregate(votes: &[Vote], n_threshold: u8) -> Result<ModerationCertificateWire, CertError> {
    if votes.is_empty() {
        return Err(CertError::BelowThreshold { n: n_threshold, got: 0 });
    }
    let first = &votes[0];
    let content_id = first.content_id;
    let strike_index = first.strike_index;
    for v in votes.iter().skip(1) {
        if v.content_id != content_id || v.strike_index != strike_index {
            return Err(CertError::InconsistentVotes);
        }
    }

    // Validate each signature individually before deduping. Bad sigs
    // shouldn't count toward the threshold even if the key is unique.
    let msg = message_to_sign(&content_id, strike_index);
    let mut accepted: Vec<(ModeratorPubKey, ModeratorSig)> = Vec::with_capacity(votes.len());
    for v in votes {
        let pubkey = VerifyingKey::from_bytes(&v.moderator_pub)
            .map_err(|_| CertError::BadPubkey)?;
        let sig = Signature::from_bytes(&v.signature.0);
        pubkey
            .verify(&msg, &sig)
            .map_err(|_| CertError::BadSignature)?;

        if accepted.iter().any(|(p, _)| p == &v.moderator_pub) {
            return Err(CertError::DuplicateSigner);
        }
        accepted.push((v.moderator_pub, v.signature));
    }

    if (accepted.len() as u8) < n_threshold {
        return Err(CertError::BelowThreshold {
            n: n_threshold,
            got: accepted.len(),
        });
    }

    Ok(ModerationCertificateWire {
        content_id,
        strike_index,
        signatures: accepted,
    })
}

/// Verify a certificate against a configured moderator set and threshold.
/// Performs every check the on-chain slash verifier will perform (modulo
/// the broader slash-evidence aggregation, which is P5).
pub fn verify(
    cert: &ModerationCertificateWire,
    moderators: &[ModeratorPubKey],
    n_threshold: u8,
) -> Result<(), CertError> {
    if (cert.signatures.len() as u8) < n_threshold {
        return Err(CertError::BelowThreshold {
            n: n_threshold,
            got: cert.signatures.len(),
        });
    }
    let msg = message_to_sign(&cert.content_id, cert.strike_index);
    let mut seen: Vec<ModeratorPubKey> = Vec::with_capacity(cert.signatures.len());
    for (pub_bytes, sig_wire) in &cert.signatures {
        if !moderators.contains(pub_bytes) {
            return Err(CertError::UnknownSigner);
        }
        if seen.contains(pub_bytes) {
            return Err(CertError::DuplicateSigner);
        }
        let pubkey = VerifyingKey::from_bytes(pub_bytes).map_err(|_| CertError::BadPubkey)?;
        let sig = Signature::from_bytes(&sig_wire.0);
        pubkey
            .verify(&msg, &sig)
            .map_err(|_| CertError::BadSignature)?;
        seen.push(*pub_bytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_moderators(m: usize) -> (Vec<SigningKey>, Vec<ModeratorPubKey>) {
        let mut rng = OsRng;
        let mut secrets = Vec::with_capacity(m);
        let mut publics = Vec::with_capacity(m);
        for _ in 0..m {
            let sk = SigningKey::generate(&mut rng);
            publics.push(sk.verifying_key().to_bytes());
            secrets.push(sk);
        }
        (secrets, publics)
    }

    /// `moderation_cert_construction` — bounty-named test.
    /// Three of five moderators sign the same strike, aggregate succeeds.
    #[test]
    fn moderation_cert_construction() {
        let (secrets, _publics) = make_moderators(5);
        let content_id: Hash = [0xAAu8; 32];
        let strike_index = 0u8;

        let votes: Vec<Vote> = secrets
            .iter()
            .take(3)
            .map(|sk| sign_vote(sk, content_id, strike_index))
            .collect();

        let cert = aggregate(&votes, 3).expect("3-of-5 must aggregate");
        assert_eq!(cert.content_id, content_id);
        assert_eq!(cert.strike_index, strike_index);
        assert_eq!(cert.signatures.len(), 3);
    }

    /// `moderation_cert_verification` — bounty-named test.
    /// 3-of-5 verifies. 2-of-5 fails.
    #[test]
    fn moderation_cert_verification() {
        let (secrets, publics) = make_moderators(5);
        let content_id: Hash = [0xBBu8; 32];
        let strike_index = 1u8;

        let three_votes: Vec<Vote> = secrets
            .iter()
            .take(3)
            .map(|sk| sign_vote(sk, content_id, strike_index))
            .collect();
        let cert = aggregate(&three_votes, 3).unwrap();
        verify(&cert, &publics, 3).expect("3-of-5 must verify");

        let two_votes: Vec<Vote> = secrets
            .iter()
            .take(2)
            .map(|sk| sign_vote(sk, content_id, strike_index))
            .collect();
        let err = aggregate(&two_votes, 3).unwrap_err();
        assert_eq!(err, CertError::BelowThreshold { n: 3, got: 2 });
    }

    #[test]
    fn rejects_duplicate_signer_in_aggregate() {
        let (secrets, _publics) = make_moderators(2);
        let content_id: Hash = [0xCCu8; 32];
        let v1 = sign_vote(&secrets[0], content_id, 0);
        let dup = v1.clone();
        let v2 = sign_vote(&secrets[1], content_id, 0);
        let err = aggregate(&[v1, dup, v2], 2).unwrap_err();
        assert_eq!(err, CertError::DuplicateSigner);
    }

    #[test]
    fn rejects_non_moderator_sig_in_verify() {
        let (secrets, publics) = make_moderators(3);
        let content_id: Hash = [0xDDu8; 32];
        // Two real moderators + one outsider
        let mut rng = OsRng;
        let outsider = SigningKey::generate(&mut rng);
        let votes = vec![
            sign_vote(&secrets[0], content_id, 0),
            sign_vote(&secrets[1], content_id, 0),
            sign_vote(&outsider, content_id, 0),
        ];
        let cert = aggregate(&votes, 3).unwrap();
        let err = verify(&cert, &publics, 3).unwrap_err();
        assert_eq!(err, CertError::UnknownSigner);
    }

    #[test]
    fn rejects_inconsistent_content_in_aggregate() {
        let (secrets, _publics) = make_moderators(2);
        let v1 = sign_vote(&secrets[0], [0xAAu8; 32], 0);
        let v2 = sign_vote(&secrets[1], [0xBBu8; 32], 0); // different content_id
        let err = aggregate(&[v1, v2], 2).unwrap_err();
        assert_eq!(err, CertError::InconsistentVotes);
    }

    #[test]
    fn rejects_inconsistent_strike_index() {
        let (secrets, _publics) = make_moderators(2);
        let cid: Hash = [0xAAu8; 32];
        let v1 = sign_vote(&secrets[0], cid, 0);
        let v2 = sign_vote(&secrets[1], cid, 1);
        let err = aggregate(&[v1, v2], 2).unwrap_err();
        assert_eq!(err, CertError::InconsistentVotes);
    }

    #[test]
    fn rejects_tampered_signature_in_verify() {
        let (secrets, publics) = make_moderators(3);
        let content_id: Hash = [0xEEu8; 32];
        let votes: Vec<Vote> = secrets
            .iter()
            .map(|sk| sign_vote(sk, content_id, 0))
            .collect();
        let mut cert = aggregate(&votes, 3).unwrap();
        cert.signatures[0].1 .0[0] ^= 0xFF; // flip a bit
        let err = verify(&cert, &publics, 3).unwrap_err();
        assert_eq!(err, CertError::BadSignature);
    }

    #[test]
    fn empty_votes_below_threshold() {
        let err = aggregate(&[], 1).unwrap_err();
        assert_eq!(err, CertError::BelowThreshold { n: 1, got: 0 });
    }
}
