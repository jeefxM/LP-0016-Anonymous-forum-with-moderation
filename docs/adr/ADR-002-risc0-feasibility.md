# ADR-002: RISC0 post-proof feasibility — conditionally feasible

- **Status:** Accepted (conditional)
- **Date:** 2026-05-28
- **Phase:** P1.5

## Context

LP-0016 requires "ZK membership proof generation takes less than 10 seconds
on a standard laptop." P1 was set up as a stop-the-line gate: if RISC0
proving for our membership construction can't hit that target, we replan
before sinking work into P2+.

We built the post-proof guest (Merkle path verification of depth 16 + SHA-256
hashing + nullifier + Shamir share placeholder) and benchmarked a real
production-mode proof.

## Benchmark result

Environment: Hetzner Ubuntu VPS, x86_64, 16 cores, 30 GB RAM, **CPU only**.
Command:
```
RISC0_DEV_MODE=0 ./target/release/bench_post_proof <post_proof.bin>
```

| Metric | Value |
|---|---|
| Wall time (prove) | **26.77 s** |
| Wall time (verify) | < 1 s |
| Total cycles | 262 144 |
| User cycles | 124 835 |
| Segments | 1 |
| Journal | 648 bytes |
| ELF size | 278 364 bytes |
| Receipt verifies | ✅ |

## Decision

**Conditionally proceed.** The naive baseline is 2.7× over budget on a
server-class CPU, but the cycle profile reveals a fixable issue, not a
fundamental one. We unblock P2 with a written optimization plan and a
hard gate to re-measure on Apple Silicon Metal before P9.

## Why the number is high (and recoverable)

The guest does only ~20 SHA-256 operations on the critical path
(16 Merkle levels + 4 helper hashes). RISC0's accelerated SHA-256 path
costs roughly 200 cycles per hash. Expected user-cycle budget for the
hashing work alone: ≈ 4 000 cycles. We measured **124 835 user cycles** —
roughly 30× the hashing cost.

The overhead concentrates in `env::read::<PrivateInputs>()` which serde-
deserialises an `[[u8; 32]; 16]` array of Merkle siblings, plus the
`[u8; 32]` secret. risc0's `serde` codec is word-oriented and pays a
notable per-byte cost. 512 bytes of siblings × ~250 cycles/byte ≈ 128 k
cycles — fits the observed gap.

Three concrete optimisations, ordered cheap-to-expensive:

1. **Bulk-read raw bytes.** Replace `env::read()` of the whole struct with
   `env::read_slice::<u32>(&mut buf)` into a fixed-size word buffer, then
   transmute / interpret. Estimated user-cycle drop: ~10× → ~12 k cycles.
2. **Halve the tree depth.** TREE_DEPTH=16 supports 65 536 members per
   instance. Depth 12 supports 4 096, sufficient for any forum demo and
   for two-instance testnet deployment. Estimated saving: 25% on hashing.
3. **GPU acceleration.** RISC0 ships `metal` and `cuda` features for
   `risc0-zkvm`. Apple Silicon Metal commonly delivers 5–10× speedups on
   the STARK prover. On an M-series MacBook this alone would put a
   non-optimised guest under budget.

Applying (1) is expected to take the wall-time from 26.77 s to
≈ 8–10 s on the Hetzner box. (1) + (2) + Metal on an M-series laptop is
the canonical "standard laptop" benchmark the bounty asks for and is
almost certain to clear the bar.

## Alternatives considered

- **Pivot off RISC0 to a Halo2 circuit.** Avoids RISC0's per-instruction
  cycle overhead entirely but requires learning a separate circuit DSL,
  hand-writing constraints, and integrating a non-RISC0 verifier into the
  LEZ slash program. Cost: 2–3 weeks of new work. Rejected — the
  optimisation path on RISC0 is shorter.
- **Move proving to Bonsai (RISC0's hosted prover).** Solves the time
  budget trivially but adds an external service dependency the bounty's
  "uses the Logos stack for all off-chain activity" framing may reject.
  Rejected for v1; available as a v2 escape hatch.
- **Abandon the bounty.** Rejected — the result is recoverable.

## Consequences

### Good

- We have a working RISC0 toolchain on Hetzner and a reproducible Docker
  build of our guest. P2+ proceed.
- The benchmark itself is reusable: `cargo run --release --bin
  bench_post_proof` is now a CI candidate (gates wall time on every PR
  once the optimisations land).

### Bad / committed-to

- **Hard gate before P9:** re-run `bench_post_proof` on an M-series
  MacBook with Metal enabled and capture a number < 10 s. If we cannot
  hit < 10 s on a laptop with the optimisations applied, we revisit this
  ADR before submission.
- The guest currently lives in a docker build that requires a Linux
  x86_64 host (Apple Silicon docker on this Mac fails on the
  risc0-guest-builder x86 image's overlayfs). Day-to-day guest builds
  happen on Hetzner until that is resolved.

## Open follow-ups

- Apply optimisation (1) (bulk read) — tracked as a P3 task.
- Set up CI gate that fails if wall-time exceeds budget.
- Benchmark on M-series Metal.
