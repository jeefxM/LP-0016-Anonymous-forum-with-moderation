//! Host-side prover wrapper for the post-proof RISC0 guest.
//!
//! `prove_post` runs the guest under the default prover and returns the
//! receipt plus the decoded `Journal`. `verify_post` re-checks a receipt
//! against the ELF's image id. The proof daemon (ADR-004) calls both.

use anyhow::{anyhow, Result};
use post_proof_core::{Journal, PrivateInputs, PublicInputs};
use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv};

pub use risc0_zkvm::Receipt;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Serialize a receipt to bytes for transport (the daemon base64-encodes
/// these for the SDK). Uses bincode; the inverse is [`receipt_from_bytes`].
pub fn receipt_to_bytes(receipt: &Receipt) -> Result<Vec<u8>> {
    bincode::serialize(receipt).map_err(|e| anyhow!("serialize receipt: {e}"))
}

/// Deserialize a receipt produced by [`receipt_to_bytes`].
pub fn receipt_from_bytes(bytes: &[u8]) -> Result<Receipt> {
    bincode::deserialize(bytes).map_err(|e| anyhow!("deserialize receipt: {e}"))
}

/// Prove non-revoked membership for one post. Blocks for as long as the
/// prover takes (tens of seconds on CPU — see ADR-002). Returns the receipt
/// and the journal the guest committed.
pub fn prove_post(
    elf: &[u8],
    private: &PrivateInputs,
    public: &PublicInputs,
) -> Result<(Receipt, Journal)> {
    let priv_bytes = private.to_bytes();
    let pub_bytes = public.to_bytes();
    let env = ExecutorEnv::builder()
        .write_slice(&priv_bytes)
        .write_slice(&pub_bytes)
        .build()?;
    let receipt = default_prover().prove(env, elf)?.receipt;
    let journal: Journal = receipt.journal.decode()?;
    Ok((receipt, journal))
}

/// Verify a receipt against the ELF's image id and return the committed
/// journal. The image id is derived from `elf`, so the caller need only
/// supply the same guest binary the daemon proves with.
pub fn verify_post(elf: &[u8], receipt: &Receipt) -> Result<Journal> {
    let image_id: [u8; 32] = compute_image_id(elf)?.into();
    receipt
        .verify(image_id)
        .map_err(|e| anyhow!("receipt verification failed: {e}"))?;
    let journal: Journal = receipt.journal.decode()?;
    Ok(journal)
}
