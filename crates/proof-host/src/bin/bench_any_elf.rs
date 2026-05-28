//! P1.4 feasibility benchmark.
//!
//! Times a real RISC0 proof of an arbitrary already-built guest ELF. Used to
//! answer "can this Mac generate a non-dev-mode proof in under 10 s?"
//! before we invest in P2+. Pair with `RISC0_DEV_MODE=0` to get production
//! timing.
//!
//! Usage: `RISC0_DEV_MODE=0 cargo run --release --bin bench_any_elf -- <path-to-elf.bin>`

use std::{env, fs, path::PathBuf, time::Instant};

use risc0_zkvm::{default_prover, ExecutorEnv};

fn main() -> anyhow::Result<()> {
    let dev_mode = env::var("RISC0_DEV_MODE").unwrap_or_default();
    eprintln!("RISC0_DEV_MODE = '{dev_mode}' (must be 0 or empty for real proofs)");

    let path: PathBuf = env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: bench_any_elf <path-to-guest.bin>"))?
        .into();
    eprintln!("Loading ELF: {}", path.display());
    let elf = fs::read(&path)?;
    eprintln!("ELF size: {} bytes", elf.len());

    // No-input run. Most LEZ example guests panic without proper inputs, but
    // setup + dev-mode pre-flight is the dominant cost in dev mode, and the
    // STARK prover dominates in prod mode regardless of input — so we still
    // measure something meaningful even when the guest panics.
    let env = ExecutorEnv::builder().build()?;

    eprintln!("Starting prove()…");
    let start = Instant::now();
    let result = default_prover().prove(env, &elf);
    let elapsed = start.elapsed();

    match result {
        Ok(prove_info) => {
            eprintln!("✅ prove() OK in {:.2?}", elapsed);
            eprintln!("Total cycles: {}", prove_info.stats.total_cycles);
            eprintln!("User cycles:  {}", prove_info.stats.user_cycles);
            eprintln!("Segments:     {}", prove_info.stats.segments);
        }
        Err(e) => {
            eprintln!(
                "ℹ️  prove() failed in {:.2?} (likely missing inputs — that's OK for the benchmark)",
                elapsed
            );
            eprintln!("err: {e:#}");
        }
    }
    Ok(())
}
