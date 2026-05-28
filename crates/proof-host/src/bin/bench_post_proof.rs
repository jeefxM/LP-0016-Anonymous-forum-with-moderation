//! P1.4 / P3.4 — real-input benchmark for our post_proof guest.
//!
//! Constructs a tiny synthetic forum instance, generates a valid membership
//! proof, and reports wall time. The host now uses the same byte-encoded
//! input format as the guest's `env::read_slice` path so the benchmark
//! reflects the P3-optimised proof.
//!
//! Usage:
//!   RISC0_DEV_MODE=0 cargo run --release --bin bench_post_proof -- <path-to-post_proof.bin>

use std::{env, fs, path::PathBuf, time::Instant};

use post_proof_core::{
    build_singleton_tree, PrivateInputs, PublicInputs, PRIVATE_INPUTS_BYTES, PUBLIC_INPUTS_BYTES,
};
use risc0_zkvm::{default_prover, sha::Digestible, ExecutorEnv};

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

    let secret = [1u8; 32];
    let (tree_root, merkle_siblings) = build_singleton_tree(&secret);
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

    let priv_bytes: [u8; PRIVATE_INPUTS_BYTES] = private.to_bytes();
    let pub_bytes: [u8; PUBLIC_INPUTS_BYTES] = public.to_bytes();

    let env_ = ExecutorEnv::builder()
        .write_slice(&priv_bytes)
        .write_slice(&pub_bytes)
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

    let image_id_bytes: [u8; 32] = risc0_zkvm::compute_image_id(&elf)?.into();
    prove_info
        .receipt
        .verify(image_id_bytes)
        .map_err(|e| anyhow::anyhow!("verify failed: {e}"))?;
    eprintln!("✅ verify() OK");
    Ok(())
}
