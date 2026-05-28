# ADR-012: Port the on-chain program to the SPEL framework on lssa

- **Status:** Accepted
- **Date:** 2026-05-29
- **Phase:** P10 (align with the current LEZ stack — unblocks IDL + live testnet)

## Context

The bounty asks for an IDL "via SPEL" and live testnet instances. Two
unknowns blocked both; community/Discord research resolved them:

- **SPEL is located:** `github.com/logos-co/spel` (`spel-framework`), an
  Anchor-style developer framework for LEZ programs. Proc macros
  (`#[lez_program]`, `#[instruction]`, `#[account(..)]`, `#[account_type]`)
  give **IDL generation, an auto-generated CLI with TX submission, and project
  scaffolding for free**. Reference build: `github.com/jimmy-claw/lez-multisig`
  (SPEL program + idl-gen + CLI + FFI + e2e + demo runbook).
- **The current LEZ core is `lssa`** (`github.com/logos-blockchain/lssa`,
  which redirects to the same `logos-execution-zone` repo) at rev
  `767b5afd388c7981bcdf6f5b5c80159607e07e5b`. SPEL pins this. The public
  testnet (`https://testnet.lez.logos.co`) runs this newer line: it uses
  **BN254 account keys** (the faucet's `recipient_pk` must be a BN254 Fr — our
  rev `8c8f5b57` used secp256k1/BIP340) and Rust 1.92.

Our program was built directly against `nssa_core` @ `8c8f5b57` with a
hand-rolled guest `main` and a bespoke `lez-runner`. That works locally (see
ADR-011, the V03State staking e2e) but cannot produce an IDL and is
incompatible with the testnet.

## Decision

Port the **on-chain program only** to `spel-framework` on `lssa`. This is a
small, contained change because the cryptographic protocol lives in
framework-independent crates.

**Carries over unchanged** (the hard, already-proven 90%):

- `membership_registry_core` — `Instruction`, `ForumState`, `verify_slash`,
  `simulate_register`, Merkle, Shamir binding, revocation. It has **no
  `nssa_core` dependency** (pure Rust: serde/sha2/ark/ed25519), so it only
  needs to compile on the new toolchain.
- `post_proof_core` + the circom circuits + trusted setup, `moderation-cert`,
  `slash-evidence`, `proof-daemon`, the SDK, and the Next.js app — all
  off-chain and framework-independent.

**Rewritten** (small): the ~220-line guest `main` becomes a `#[lez_program]`
module whose `#[instruction]` handlers call the existing core logic.
`#[lez_program(instruction = "membership_registry_core::Instruction")]` reuses
our enum verbatim; `#[account_type]` on `ForumState` puts it in the IDL.

**Replaced** (net simplification): `lez-runner` → SPEL's auto-generated CLI
(tx submission, PDA derivation, wallet integration). The daemon's chain calls
re-point at it.

## Alternatives considered

- **Stay on `8c8f5b57` (the old stack).** Everything works locally, but no
  IDL and no testnet — two explicit bounty asks unmet. Rejected.
- **Hand-roll an IDL + a BN254 runner without SPEL.** Reinvents what SPEL
  gives for free and diverges from the framework Logos expects. Rejected.

## Consequences

- Unblocks three bounty items in one effort: **IDL via SPEL** (free from the
  macros), **live testnet** (matching stack), and an **auto-CLI** (+
  `spel inspect` decoding `ForumState`).
- BN254 account signing is handled by the SPEL CLI / lssa and is transparent
  to our guest logic (handlers read pre-states and write post-states; they
  never construct account keys). Our Ed25519 moderation certs are
  application-level (inside `verify_slash`) and independent of the chain's
  account-key scheme — unaffected.
- The risc0 `ruint 1.17` pin (needed for the old 1.88 docker builder)
  disappears on the newer toolchain.

## Risks

1. **Toolchain** (medium): Rust 1.92+ guest build via a SPEL-compatible risc0
   builder. Host has Rust 1.94 + cargo-risczero 3.0.5; the guest toolchain
   compatibility is validated by a scaffold smoke test before porting logic.
2. **`nssa_core` API delta** `8c8f5b57 → 767b5afd` (medium-low): `program.rs`
   was refactored, but SPEL's prelude abstracts the program API and the core
   is nssa-free, so the blast radius is the rewritten guest only.
3. **Faucet** (low, external): BN254-keyed and rate-limited (~1/23h per IP).
   Paces the live testnet step.
4. **Disk** on the build host (operational): keep an eye on free space during
   the heavier SPEL/guest builds.

## Plan (phased)

1. Stand up the SPEL toolchain on the build host; scaffold smoke test
   (`spel init` → `make build` → `make idl` on a hello program).
2. Compile `membership_registry_core` against the new toolchain.
3. Re-express the guest as a `#[lez_program]` module reusing the core.
4. Generate the IDL (`make idl`); commit it.
5. Deploy to the testnet, fund a BN254 member via the faucet, run the live
   Initialize → stake → Register → Slash e2e.
6. Two live instances with different K/N-of-M (+ a K=2 circuit).

The V03State staking e2e (ADR-011) and the off-chain stack remain the
fallback proof if any testnet step stalls on external factors.
