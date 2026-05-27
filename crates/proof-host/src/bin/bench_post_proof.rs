//! P1.4 — real-input benchmark for our post_proof guest.
//!
//! Constructs a tiny synthetic forum instance, generates a valid membership
//! proof, and reports wall time. The crypto operations match the guest's
//! exactly so the Merkle path verifies.
//!
//! Usage:
//!   RISC0_DEV_MODE=0 cargo run --release --bin bench_post_proof -- <path-to-post_proof.bin>

use std::{env, fs, path::PathBuf, time::Instant};

use risc0_zkvm::{default_prover, sha::Digestible, ExecutorEnv};
use serde::Serialize;
use sha2::{Digest, Sha256};

const TREE_DEPTH: usize = 16;

#[derive(Serialize)]
struct PrivateInputs {
    secret: [u8; 32],
    merkle_siblings: [[u8; 32]; TREE_DEPTH],
    merkle_path_bits: u32,
}

#[derive(Serialize)]
struct PublicInputs {
    tree_root: [u8; 32],
    epoch: u64,
    content_id: [u8; 32],
}

fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn commitment_of(secret: &[u8; 32]) -> [u8; 32] {
    sha256_concat(&[b"commit", secret])
}

fn main() -> anyhow::Result<()> {
    let dev_mode = env::var("RISC0_DEV_MODE").unwrap_or_default();
    eprintln!("RISC0_DEV_MODE = '{dev_mode}' (must be 0 or empty for real proofs)");

    let path: PathBuf = env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: bench_post_proof <path-to-post_proof.bin>"))?
        .into();
    eprintln!("Loading ELF: {}", path.display());
    let elf = fs::read(&path)?;
    eprintln!("ELF size: {} bytes", elf.len());

    // Construct a valid synthetic instance.
    // Member at leaf index 0, all siblings = zero (path_bits = 0 = left child every level).
    let secret = [1u8; 32];
    let commitment = commitment_of(&secret);
    let zero = [0u8; 32];
    let merkle_siblings = [zero; TREE_DEPTH];

    // Compute the matching root by hashing up the tree with all-zero siblings.
    let mut cur = commitment;
    for _level in 0..TREE_DEPTH {
        cur = sha256_concat(&[b"node", &cur, &zero]);
    }
    let tree_root = cur;

    let private = PrivateInputs {
        secret,
        merkle_siblings,
        merkle_path_bits: 0,
    };
    let public = PublicInputs {
        tree_root,
        epoch: 1,
        content_id: [42u8; 32],
    };

    let env_ = ExecutorEnv::builder()
        .write(&private)?
        .write(&public)?
        .build()?;

    eprintln!("Starting prove()…");
    let start = Instant::now();
    let prove_info = default_prover().prove(env_, &elf)?;
    let elapsed = start.elapsed();

    eprintln!("✅ prove() OK in {:.2?}", elapsed);
    eprintln!("Total cycles: {}", prove_info.stats.total_cycles);
    eprintln!("User cycles:  {}", prove_info.stats.user_cycles);
    eprintln!("Segments:     {}", prove_info.stats.segments);
    eprintln!(
        "Journal len:  {} bytes  digest: {}",
        prove_info.receipt.journal.bytes.len(),
        hex::encode(prove_info.receipt.journal.digest().as_bytes()),
    );

    // Quick sanity-check verify on the receipt.
    let image_id_bytes: [u8; 32] = risc0_zkvm::compute_image_id(&elf)?.into();
    prove_info
        .receipt
        .verify(image_id_bytes)
        .map_err(|e| anyhow::anyhow!("verify failed: {e}"))?;
    eprintln!("✅ verify() OK");
    Ok(())
}
