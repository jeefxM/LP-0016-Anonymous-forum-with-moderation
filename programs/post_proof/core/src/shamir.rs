//! Shamir secret sharing over BN254 Fr (254-bit prime field).
//!
//! ## Construction
//!
//! For each member, a `(K-1)`-degree polynomial `p(x)` is defined whose
//! constant term is the member's identity secret (interpreted as a Fr
//! element). The other K-1 coefficients are derived deterministically
//! from the secret so the polynomial is identical across all posts by
//! the same member.
//!
//! For each post, the guest evaluates `p` at a post-specific `x` derived
//! from `(secret, content_id)` and emits `(x, y)` as the post's share.
//!
//! Collecting K shares from K distinct posts (via K moderation
//! certificates) gives K points on `p`; Lagrange interpolation at `x=0`
//! recovers the secret.
//!
//! Fewer than K shares reveal nothing because a `(K-1)`-degree polynomial
//! has K coefficients and ≥ K points are needed to determine it uniquely.
//!
//! ## Field choice
//!
//! ark-bn254::Fr is a 254-bit prime field — the scalar field of the
//! BN254 elliptic curve. Already a transitive dependency through
//! risc0_groth16. ADR-008 (TBD) records the choice.

#![allow(clippy::module_name_repetitions)]

extern crate alloc;

use alloc::vec::Vec;
pub use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

/// Domain separators for deterministic coefficient + x derivation.
pub const COEFF_TAG: &[u8] = b"shamir/coeff";
pub const SHARE_X_TAG: &[u8] = b"shamir/x";

/// Convert a 32-byte secret into a field element (reduced mod p).
pub fn secret_to_fr(secret: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(secret)
}

/// Serialize a field element to a fixed 32-byte buffer (little-endian).
pub fn fr_to_bytes(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = f.into_bigint().to_bytes_le();
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Parse a field element from 32 bytes (little-endian).
pub fn fr_from_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Generate the K coefficients of a member's polynomial. The constant
/// term `c[0]` is the secret; the higher coefficients are deterministic
/// SHA-256 outputs of `(secret, COEFF_TAG, i)` reduced into Fr. This makes
/// every post by the same member share the same polynomial — required so
/// shares collected from K different posts lie on the same curve.
pub fn polynomial_coefficients(secret: &[u8; 32], k_threshold: usize) -> Vec<Fr> {
    assert!(k_threshold >= 1, "k_threshold must be >= 1");
    let mut coeffs = Vec::with_capacity(k_threshold);
    coeffs.push(secret_to_fr(secret));
    for i in 1..k_threshold {
        let mut h = Sha256::new();
        h.update(COEFF_TAG);
        h.update(secret);
        h.update((i as u32).to_le_bytes());
        let bytes: [u8; 32] = h.finalize().into();
        coeffs.push(Fr::from_le_bytes_mod_order(&bytes));
    }
    coeffs
}

/// Compute the post-specific `x` coordinate from `(secret, content_id)`.
/// Different content_id → different x even with the same secret, which is
/// what makes each post a distinct share.
pub fn derive_share_x(secret: &[u8; 32], content_id: &[u8; 32]) -> Fr {
    let mut h = Sha256::new();
    h.update(SHARE_X_TAG);
    h.update(secret);
    h.update(content_id);
    let bytes: [u8; 32] = h.finalize().into();
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Evaluate the polynomial defined by `coeffs` at `x` via Horner's method.
pub fn poly_eval(coeffs: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::zero();
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Lagrange interpolation: given K distinct (x, y) points, recover the
/// polynomial value at `target`. To recover the secret, call with
/// `target = Fr::zero()`.
///
/// Returns `Err` if any two x-coordinates collide (would make a denominator
/// zero) or if `points` is empty.
pub fn lagrange_interpolate(points: &[(Fr, Fr)], target: Fr) -> Result<Fr, &'static str> {
    if points.is_empty() {
        return Err("no points to interpolate");
    }
    // Check for duplicate x's. K should be small (≤ ~10 in practice) so
    // an n^2 dedupe is fine.
    for i in 0..points.len() {
        for j in 0..i {
            if points[i].0 == points[j].0 {
                return Err("duplicate x-coordinate");
            }
        }
    }

    let mut total = Fr::zero();
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut num = Fr::from(1u64);
        let mut den = Fr::from(1u64);
        for (j, (xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            num *= target - xj;
            den *= xi - xj;
        }
        let inv = den.inverse().ok_or("non-invertible denominator")?;
        total += *yi * num * inv;
    }
    Ok(total)
}

/// Compute a single post's share. Convenience for the host side; the
/// guest performs the equivalent computation inline.
pub fn compute_share(secret: &[u8; 32], k_threshold: usize, content_id: &[u8; 32]) -> (Fr, Fr) {
    let coeffs = polynomial_coefficients(secret, k_threshold);
    let x = derive_share_x(secret, content_id);
    let y = poly_eval(&coeffs, x);
    (x, y)
}

/// Reconstruct the secret from K shares via Lagrange at x=0. Returns the
/// secret as a 32-byte little-endian Fr-encoded buffer.
pub fn reconstruct_secret(shares: &[(Fr, Fr)]) -> Result<[u8; 32], &'static str> {
    let secret_fr = lagrange_interpolate(shares, Fr::zero())?;
    Ok(fr_to_bytes(&secret_fr))
}

/// Re-encode a Fr as a `Vec<u8>` for serialisation across the host/guest
/// or LEZ instruction boundary.
pub fn fr_to_vec(f: &Fr) -> Vec<u8> {
    let mut out = Vec::new();
    f.serialize_compressed(&mut out)
        .expect("Fr always serialises");
    out
}

pub fn fr_from_vec(bytes: &[u8]) -> Result<Fr, &'static str> {
    Fr::deserialize_compressed(bytes).map_err(|_| "invalid Fr encoding")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_secret(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn polynomial_constant_term_is_secret() {
        let secret = dummy_secret(0xAB);
        let coeffs = polynomial_coefficients(&secret, 3);
        assert_eq!(coeffs.len(), 3);
        assert_eq!(coeffs[0], secret_to_fr(&secret));
    }

    #[test]
    fn eval_at_zero_returns_secret() {
        let secret = dummy_secret(0x42);
        let coeffs = polynomial_coefficients(&secret, 4);
        assert_eq!(poly_eval(&coeffs, Fr::zero()), secret_to_fr(&secret));
    }

    #[test]
    fn reconstructs_from_exactly_k_shares() {
        let secret = dummy_secret(0x77);
        let k = 3;
        let coeffs = polynomial_coefficients(&secret, k);

        let mut shares = Vec::new();
        for i in 0..k {
            let cid = {
                let mut c = [0u8; 32];
                c[0] = i as u8;
                c
            };
            let x = derive_share_x(&secret, &cid);
            let y = poly_eval(&coeffs, x);
            shares.push((x, y));
        }
        let recovered = reconstruct_secret(&shares).unwrap();
        assert_eq!(recovered, fr_to_bytes(&secret_to_fr(&secret)));
    }

    #[test]
    fn k_minus_one_shares_does_not_reveal_secret() {
        // Information-theoretically a single (K-1) subset is consistent
        // with infinitely many secrets. We can't prove that within a
        // single test, but we can prove that the Lagrange interpolation
        // at x=0 from K-1 points gives a DIFFERENT value than the real
        // secret, even when an attacker tries it.
        let secret = dummy_secret(0xDE);
        let k = 4;
        let coeffs = polynomial_coefficients(&secret, k);
        let mut shares = Vec::new();
        for i in 0..k - 1 {
            // only K-1 shares
            let cid = {
                let mut c = [0u8; 32];
                c[0] = i as u8;
                c
            };
            let x = derive_share_x(&secret, &cid);
            let y = poly_eval(&coeffs, x);
            shares.push((x, y));
        }
        // We CAN run Lagrange with K-1 points — it gives some value, but
        // it won't equal the real secret (because the polynomial has
        // degree K-1, and K-1 points determine a degree-K-2 polynomial
        // not the original one).
        let attempted = reconstruct_secret(&shares).unwrap();
        assert_ne!(attempted, fr_to_bytes(&secret_to_fr(&secret)));
    }

    #[test]
    fn reconstruction_with_extra_shares_still_works() {
        // K+1 shares should also reconstruct correctly (any K-subset works).
        let secret = dummy_secret(0xBE);
        let k = 3;
        let coeffs = polynomial_coefficients(&secret, k);
        let mut shares = Vec::new();
        for i in 0..k + 1 {
            let cid = {
                let mut c = [0u8; 32];
                c[0] = i as u8;
                c
            };
            let x = derive_share_x(&secret, &cid);
            let y = poly_eval(&coeffs, x);
            shares.push((x, y));
        }
        let recovered = reconstruct_secret(&shares).unwrap();
        assert_eq!(recovered, fr_to_bytes(&secret_to_fr(&secret)));
    }

    #[test]
    fn duplicate_x_returns_err() {
        let secret = dummy_secret(0x01);
        let coeffs = polynomial_coefficients(&secret, 2);
        let x = derive_share_x(&secret, &[0u8; 32]);
        let y = poly_eval(&coeffs, x);
        let shares = vec![(x, y), (x, y)];
        assert!(reconstruct_secret(&shares).is_err());
    }
}
