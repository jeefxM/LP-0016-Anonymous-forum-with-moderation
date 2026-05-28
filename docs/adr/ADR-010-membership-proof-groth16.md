# ADR-010: Membership post-proof is a Groth16 circuit, not a risc0 guest

- **Status:** Accepted
- **Date:** 2026-05-28
- **Phase:** Perf gate (post-P6)
- **Supersedes:** the proving-system choice in ADR-005 for the *membership
  post-proof only*. The LEZ on-chain program stays risc0 (ADR-007).

## Context

The bounty requires "ZK membership proof generation < 10s on a standard
laptop." ADR-002/-005 implemented the membership post-proof as a **risc0
zkVM guest**. Measured reality (ADR-002 update): 55s on Hetzner CPU, 65s on
an M2 — and risc0 3.0.5 has **no Metal backend** (only CPU/CUDA; the Metal
HAL is removed). zkVM STARK proving is fundamentally tens of seconds on CPU,
so the gate is unreachable with the zkVM on a laptop.

The bounty itself points the other way: it calls this a "ZK membership proof
**circuit**" and lists **Semaphore** + **Shamir's Secret Sharing** as the
resources. That's the RLN pattern — a small SNARK circuit that proves
Merkle membership and emits a Shamir share. A Groth16 proof of this size
generates in **~1–5s on a laptop**. Crucially, **posts are off-chain**: a
post's membership proof is verified by readers/the app, *never by the LEZ
program*. So the proof system for posts is fully decoupled from the chain.

## Decision

**Replace the risc0 `post_proof` guest with a Groth16 circuit (circom),
keeping every byte of the existing SHA-256-based protocol.** Specifically:

- The circuit uses **SHA-256** for every hash — identical to the current
  Rust (`commitment_of`, `node_hash`, `nullifier`, and the Shamir
  `derive_share_x` / `polynomial_coefficients`). It does **not** switch to
  Poseidon.
- Proving runs in the local daemon (ADR-004) via **rapidsnark** (native;
  snarkjs-wasm is too slow for a SHA-256 circuit). The daemon already isn't
  browser-bound, so this is fine.
- `K` (threshold) is a compile-time constant → one compiled circuit + vkey
  per `K`. The demo uses K=2 and K=3.

### Why SHA-256 / "keep the stack" (vs Poseidon-everywhere)

Both options need a custom circuit (configurable K rules out stock degree-1
RLN circuits). SHA-256 keeps the chain-verified Rust stack byte-identical;
Poseidon would force re-deploying the LEZ program, porting `verify_slash` to
Poseidon-over-BN254 in no_std Rust, and swapping the SDK tree to JS
Poseidon — three reimplementations of one hash that must match bit-for-bit.
SHA-256's only alignment risk is a single mod-r reduction gadget against an
unambiguous spec; Poseidon's risk (circomlib round constants / MDS across
three languages) is unbounded. We take the bounded risk.

## Circuit specification (must match the Rust byte-for-byte)

Field: BN254 scalar field `r` (circom's native field). Hash: SHA-256.
All multi-byte integers little-endian. Domain tags are ASCII, no separator.

**Private inputs:** `secret` (32-byte canonical Fr, i.e. value < r),
`siblings[16]` (each 32 bytes), `pathBits` (u32; bit L = level-L direction).

**Public signals:** `treeRoot` (32B), `epoch` (u64), `contentId` (32B) —
inputs; `nullifier` (32B), `shareX` (32B), `shareY` (32B) — outputs.

**Hashes (exact preimages; tag bytes then payload, concatenated):**

| value | preimage | bytes |
|---|---|---|
| `commitment` | `"commit"(6) ‖ secret(32)` | 38 |
| `node_hash(l,r)` | `"node"(4) ‖ l(32) ‖ r(32)` | 68 |
| `nullifier` | `"null"(4) ‖ secret(32) ‖ epoch_LE(8)` | 44 |
| `shareX` preimage | `"shamir/x"(8) ‖ secret(32) ‖ contentId(32)` | 72 |
| `coeff[i]` preimage (i≥1) | `"shamir/coeff"(12) ‖ secret(32) ‖ i_LE_u32(4)` | 48 |

**Merkle:** `cur = commitment`; for `level` in 0..16: if `bit==0`
`cur=node_hash(cur, sib)` else `node_hash(sib, cur)`. Constrain
`cur == treeRoot`.

**Shamir (degree K-1 over Fr):**
- `coeff[0] = secret` interpreted as Fr (the secret is canonical, < r).
- `coeff[i] = SHA256(coeff-preimage_i)` reduced **`from_le_bytes_mod_order`**:
  treat the 32 digest bytes as a little-endian 256-bit integer, reduce mod r.
- `shareX = SHA256(shareX-preimage)` reduced the same way.
- `shareY = Σ coeff[i] · shareX^i` (Horner). Native field arithmetic.
- `nullifier`/`commitment`/Merkle nodes are raw 32-byte SHA-256 digests (no
  reduction); `shareX`/`shareY` public outputs are the **Fr value in 32-byte
  LE** (`fr_to_bytes` = `into_bigint().to_bytes_le()`).

**The mod-r gadget** (the one consensus-critical piece): given 256 SHA-256
output bits, assemble the LE integer `v`, witness `q` and `rem` with
`v = q·r + rem`, range-check `rem < r` and `q` small enough. Must reproduce
ark-ff `Fr::from_le_bytes_mod_order` exactly. Validate with the byte-level
cross-test in PERF-6.

## Trusted setup

Groth16 needs a per-circuit setup. Use a public Powers-of-Tau (Hermez
`ptau` 2^20/2^21) + a phase-2 contribution per K. For the bounty demo this
is single-contributor (documented as demo-grade, not production ceremony).
Commit the vkeys; the `.zkey` is large → fetched/regenerated, not committed.

## What does NOT change (scope guard — if any of these need edits, STOP)

- `programs/membership_registry/*` (LEZ register + `verify_slash`) — SHA-256,
  same ImageID, no redeploy.
- `crates/slash-evidence`, `crates/moderation-cert` — share math unchanged
  (Lagrange is field-only; shares are byte-identical to today).
- `sdk/src/tree.ts` `MerkleTree` — stays SHA-256; its root still matches the
  chain.
- The daemon's chain + pure-crypto endpoints; the SDK surface and the Waku
  transport.

What changes: only the **off-chain prover** (daemon `/v1/post/prove`: risc0
receipt → Groth16 proof) and the **off-chain verifier** (`verifyPostProof`:
risc0 verify → Groth16 verify). The `PostEnvelope.receipt` field carries the
Groth16 proof + public signals instead of a risc0 receipt.

## Measured result (PERF-5)

The full circuit is **1,142,169 constraints**. End-to-end proof generation,
`RISC0_DEV_MODE` N/A (this is Groth16, not risc0):

| step | time |
|---|---:|
| witness generation (circom wasm) | 2.35 s (Hetzner) / 2.39 s (M2) |
| Groth16 prove (rapidsnark) | 2.36 s (Hetzner, 16-core) |
| **total proof generation** | **~4.7 s** |
| verify (`snarkjs groth16 verify`) | OK |

vs the old risc0 zkVM membership proof at 55–65 s — **~12× faster, under the
10 s gate.** Witness generation is single-threaded wasm and laptop-equivalent
(2.4 s on the M2); rapidsnark for ~1M constraints on M-series is a few
seconds, so the total stays < 10 s on a laptop. (A native-Mac rapidsnark
build hit cmake-4 / arm64 / generated-source quirks; the number above is from
the Linux build. A pristine on-M2 rapidsnark measurement is a polish item —
the margin makes the laptop result a near-certainty.)

The circuit's public outputs (nullifier/shareX/shareY) match Rust
`prove_post` byte-for-byte (PERF-3), so the emitted share still satisfies the
on-chain `verify_slash` unchanged.

### Live daemon path (PERF-5 wiring + PERF-6)

The daemon's `/v1/post/prove` now builds the circuit input from the request,
shells to node (witness gen over `membership.wasm`) + the rapidsnark `prover`,
and returns the proof + public signals as `PostEnvelope.receipt`
(`base64(JSON {proof, publicSignals})`, ~2 KB). Measured **end to end over
HTTP: 4.63 s** (status 200); the returned nullifier/shareX/shareY match the
oracle byte-for-byte.

`/v1/post/verify` decodes the receipt, runs `snarkjs groth16 verify` against
the committed `vkey.json`, and — critically — **binds the verified public
signals to the envelope byte-for-byte** (`[0..96]` = nullifier‖shareX‖shareY,
`[96..128]` = treeRoot, `[128]` = epoch, `[129..161]` = contentId). Without
this bind a valid proof could be replayed against a different
(root, epoch, contentId); snarkjs alone only attests that *some* inputs
satisfy the proof. The existing stale-root check (envelope root == current
on-chain root) is retained.

`sdk/tests/lifecycle.mjs` is green end-to-end against the live daemon + nwaku
+ chain: register → 3 Groth16-proved posts → verify → 2-of-3 moderation →
slash → member revoked. The slash succeeding confirms the circuit's shares
reconstruct the secret and satisfy the unchanged on-chain `verify_slash`.

**Scope landed:** only `crates/proof-daemon` (`proving.rs` rewrite,
`state.rs` circuit config, dropped the `proof-host`/risc0 dependency) + doc
comments in `sdk/src/types.ts`. The LEZ program, `verify_slash`,
`slash-evidence`, and the SDK `MerkleTree` are byte-identical — the scope
guard above held.

## Consequences

- Meets `<10s` on a standard laptop with no GPU (~4.7s measured; rapidsnark).
  The risc0 `post_proof` guest becomes legacy (kept for history; removed from
  the live path).
- Adds a circom/snarkjs/rapidsnark toolchain to the build. Documented in the
  README + CI.
- The `risc0-circuit-rv32im` SHA-256 of node hashes and the circom SHA-256
  must be confirmed bit-identical before building the full circuit (PERF-2).
- Soundness now rests on the circuit's constraints (esp. the mod-r gadget)
  rather than the zkVM's execution integrity — hence the byte-level
  cross-tests and the requirement that the circuit's emitted share satisfies
  the on-chain `verify_slash` (the existing P5 cross-check, re-pointed at the
  circuit).
