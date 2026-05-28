# ADR-002: RISC0 post-proof feasibility — conditionally feasible, GPU is the path

- **Status:** Accepted (conditional)
- **Date:** 2026-05-28 (revised after P3 measurements)
- **Phase:** P1.5 / P3.4

## Context

LP-0016 requires "ZK membership proof generation takes less than 10 seconds
on a standard laptop." P1 was set up as a stop-the-line gate: if RISC0
proving for our membership construction can't hit that target, we replan
before sinking work into P2+.

We built the post-proof guest and have now benchmarked three variants on a
Hetzner Ubuntu CPU box (x86_64, 16 cores, 30 GB RAM, no GPU).

## Benchmarks

Environment: Hetzner CPU only, all three runs use `RISC0_DEV_MODE=0`.

| Variant | Wall time | Total cycles | User cycles | Segments |
|---|---:|---:|---:|---:|
| P1 baseline (serde struct read) | 26.77 s | 262 144 | 124 835 | 1 |
| P3 attempt 1 (read u32 + rebuild struct) | 30.17 s | 262 144 | 196 975 | 1 |
| **P3 attempt 2 (byte-slice direct, no struct)** | **28.07 s** | **262 144** | **195 854** | **1** |

Variance is within ~3 s of run noise. The cycle counts move but wall time
does not. ELF size shrank from 278 KB → 243 KB across attempts.

## The key learning (revised model)

RISC0's STARK prover is **segment-rounded**. The wall time is dominated by
the cost of generating one segment's STARK, regardless of how much of the
segment's cycle budget the guest actually uses. Our guest's true work
(~20 SHA-256 hashes ≈ 4 000 cycles in the inner loop) is invisible against
the segment overhead.

Concretely: all three benchmark runs ran exactly **one segment** of
262 144 total cycles. The proof cost is ~27–30 s for that segment on
Hetzner CPU. We could push user cycles to ~10 000 and the wall time would
still be ~27 s; we could push user cycles to 250 000 and the wall time
would still be ~28 s. The cost is the segment, not the work.

The original ADR (v1) predicted "10× user-cycle drop ⇒ ~3 s wall time."
That was wrong. The right model is: **either fit in a single segment with
faster per-segment hardware (GPU), or split work across multiple smaller
segments only if RISC0 supports sub-segment proving (it does not, in
3.0.5).**

## Decision (revised)

**Conditionally proceed. The path to < 10 s is GPU acceleration on the
target benchmark laptop (M-series Metal or CUDA), not user-cycle
optimisation.** We unblock P2+ with two locked-in gates:

1. Before merging the P9 submission, run `bench_post_proof` on a
   reference M-series MacBook with `risc0-zkvm` `metal` feature enabled.
   If wall time is < 10 s, we ship.
2. If Metal is also > 10 s on a current M-series, we re-open this ADR
   with a pivot to Bonsai (hosted GPU prover) or off-RISC0 circuit. We
   do **not** pre-emptively pivot now because Apple Silicon Metal on
   risc0-zkvm is commonly reported at 5–10× CPU baseline.

## Why we keep the byte-slice (P3 attempt 2) code anyway

Even though it didn't move wall time, the byte-slice path is cleaner and
host-testable:

- `prove_post_from_bytes(priv: &[u8; N], pub: &[u8; M]) -> Result<Journal, _>`
  in `post_proof_core` is what both the guest and the host bench call.
- All six unit tests run in pure Rust against the same code path.
- The guest binary shrank ~13 % (278 → 243 KB).
- We're not paying for the optimisation in wall time; we're not paying
  for it in code complexity either — the new shape is *simpler*.

## What we are NOT doing

- ~~`env::read` of a serde struct~~ — kept the dependency removal.
- ~~Pre-emptive pivot to a Halo2 circuit~~ — too much new infrastructure
  before we've measured Metal.
- ~~Bonsai hosted prover for v1~~ — adds an external dependency the
  bounty's "Logos stack for all off-chain activity" wording is ambiguous
  about. Available as a fallback.

## Update (P5.2): real Shamir share crosses the segment boundary

After P5.2 the post_proof guest computes the real BN254 Fr Shamir share
(not the XOR placeholder). Re-bench on the same Hetzner CPU:

| | Before (P3) | After real Shamir (P5.2) |
|---|---:|---:|
| Wall time | 28.07 s | **54.87 s** |
| Total cycles | 262 144 (1 seg) | **524 288 (2 seg)** |
| User cycles | 195 854 | 225 916 |

User cycles only rose ~30 k, but that was enough to spill past the
262 144 single-segment budget into a **second segment** — and because
wall time is segment-bound (the core finding above), crossing that line
roughly doubled the time.

Two levers, in order of preference:

1. **Trim ~30 k user cycles to stay in one segment.** The new cost is
   ark-bn254 `from_le_bytes_mod_order` (called ~4× for coeff/x derivation)
   plus `fr_to_bytes` ×2. Options: derive the K-1 polynomial coefficients
   with fewer modular reductions; reuse the reduced secret Fr; or shrink
   the Merkle proof side (TREE_DEPTH 16→12 saves ~4 node hashes). Getting
   back under 262 144 returns us to ~27 s on this CPU.
2. **Metal.** Still the decisive lever. Even at 2 segments, a 5–10×
   Apple-Silicon speedup lands 54.87 s → 5–11 s. The pre-P9 gate now has
   less margin, so we should ALSO do (1).

Revised pre-P9 gate: apply optimisation (1), then bench on M-series Metal.
Target < 10 s. If (1)+Metal still misses, escalate to Bonsai or an
off-RISC0 circuit per the alternatives above.

## Open follow-ups

- **Pre-P9 gate:** re-bench on M-series Metal with optimisations applied.
  Tracked as task #16.
- **CI bench:** add a CI job that runs `bench_post_proof` on a known
  runner and fails if wall time regresses by > 20 %. Useful even before
  Metal validates the budget, to catch unexpected regressions.
- **TREE_DEPTH 16 → 12.** Probably not worth the work if Metal closes the
  gap. Park as a contingency.
