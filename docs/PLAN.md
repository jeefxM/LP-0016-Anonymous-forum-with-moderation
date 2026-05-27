# Plan: Anonymous Forum Protocol — Phased Implementation

> **Status:** Draft v0.1
> **Companion to:** `docs/SPEC.md`
> **Phase:** 2 of 4 in the spec-driven workflow (Specify → **Plan** → Tasks → Implement)

This plan turns the spec into an ordered build. Each phase has a clear goal,
deliverables, a verification checkpoint, and an explicit dependency on prior
phases. Phases the human approves move into Phase 3 (Tasks) one at a time.

---

## Major components and dependencies

```
                ┌─────────────────────────┐
                │ P0  Repo + tooling      │
                └────────────┬────────────┘
                             ▼
                ┌─────────────────────────┐
                │ P1  Crypto spike        │ ◄── highest-risk thing,
                │     (RISC0 + RLN proof) │     done first to de-risk
                └────────────┬────────────┘
                             ▼
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
 ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
 │ P2  LEZ     │      │ P3  Post-   │      │ P4  Mod cert│
 │     registry│      │     proof   │      │     library │
 │     program │      │     guest   │      │     (off-   │
 │             │      │             │      │     chain)  │
 └──────┬──────┘      └──────┬──────┘      └──────┬──────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             ▼
                ┌─────────────────────────┐
                │ P5  Slash pipeline      │
                │     (share aggregation  │
                │      → slash submit)    │
                └────────────┬────────────┘
                             ▼
                ┌─────────────────────────┐
                │ P6  SDK + Waku transport│
                │     (the public API)    │
                └────────────┬────────────┘
                             ▼
                ┌─────────────────────────┐
                │ P7  Reference forum app │
                │     (Basecamp)          │
                └────────────┬────────────┘
                             ▼
   ┌─────────────────────────┴─────────────────────────┐
   ▼                                                   ▼
┌─────────────────────────┐              ┌──────────────────────────┐
│ P8  Docs + IDL          │              │ P9  Demo + deployments + │
│ (can start during P5+)  │              │     video + submission   │
└─────────────────────────┘              └──────────────────────────┘
```

---

## Phase 0 — Foundations

**Goal:** A buildable, lintable, testable monorepo skeleton with CI green on
an empty hello-world commit. No protocol logic yet.

**Deliverables:**

- `forum-protocol/` repo initialized, license MIT, README placeholder.
- Cargo workspace + pnpm workspace wired together at the root.
- Empty crates and packages matching the structure in `SPEC.md`.
- ESLint custom rule `no-direct-protocol-imports` scaffolded (rule body can be
  trivial for now — just needs to be wired into CI).
- `Justfile` with `dev`, `build`, `test`, `lint`, `demo` targets — even if
  they only echo "TODO" for now.
- GitHub Actions: `lint + test` on PR, `build artifacts` on push to `main`.
- ADR template in `docs/adr/`. First ADR written:
  **ADR-001: Use Waku Store only, defer Codex.**
- First-time `cargo build --release` completed (one-time ~30 min cost).

**Verify:**

- `pnpm lint && pnpm test && cargo clippy && cargo test` all pass on the empty repo.
- CI is green.

**Risk / blocker:**

- First Rust + RISC0 build will be slow. Run it overnight if needed.

---

## Phase 1 — Crypto spike (RLN-style proof in RISC0)

**Goal:** Prove the load-bearing assumption that we can generate an RLN-style
"I'm in the tree, here's a Shamir share bound to (epoch, content)" proof
inside a RISC0 guest in under 10 seconds on a MacBook M-series.

**Why first:** If RISC0 can't hit <10s for this proof, we have to change
strategy (separate Halo2/Circom circuit, different chain, or scope cut). We
need to know this in week 1, not week 5.

**Deliverables:**

- `programs/post_proof/methods/guest/src/bin/post_proof.rs` — minimal RISC0
  guest that:
  - Takes (private) identity_secret, Merkle path, content_id, epoch
  - Takes (public) tree_root, epoch, content_id
  - Computes commitment from secret
  - Verifies Merkle path against root
  - Computes nullifier = poseidon(secret, epoch)
  - Computes Shamir share = (x = nullifier, y = secret_lower_half + poseidon(secret, content_id) * nullifier)
  - `env::commit`s (commitment_in_root: bool, nullifier, share)
- A host-side benchmark binary that generates a real proof and reports wall time.
- Benchmark result documented in `docs/adr/ADR-002-risc0-feasibility.md`.

**Verify:**

- Real proof under 10s on the dev machine with `RISC0_DEV_MODE=0`.
- Tree size 2^16 (matches realistic forum-instance scale).
- ADR-002 says **proceed** or **pivot**.

**Risk / blocker:**

- If RISC0 + Poseidon is too slow, we either drop to smaller tree or move the
  proof to a Halo2 circuit run outside RISC0 (and only the slash verifier
  stays in LEZ). Both are recoverable, but extend the timeline by ~1 week.

**Stop-the-line:** If P1 fails to hit target, freeze P2–P9 and re-plan.

---

## Phase 2 — LEZ membership registry program

**Goal:** A deployable LEZ program with `Register` and `Slash` instructions.
At this phase the `Slash` instruction's signature/share verification is
**stubbed** to `panic!("not implemented")` — we wire it up in P5. We're
proving end-to-end on-chain plumbing first.

**Deliverables:**

- `programs/membership_registry/core/src/lib.rs` — `Instruction` enum +
  state types.
- `programs/membership_registry/methods/guest/src/bin/membership_registry.rs` —
  the guest program (`Register` fully implemented, `Slash` stub).
- `crates/lez-runner/` — host-side runner that builds + submits register/slash
  transactions, following the `examples/program_deployment` runner pattern.
- Local-sequencer integration test: register two members, query registry
  state, verify both commitments present.

**Verify:**

- `cargo risczero build` produces a deployable `.bin`.
- `wallet deploy-program` on local sequencer succeeds.
- Local-sequencer e2e test: 5 registrations pass, 5 reads pass.
- `cargo clippy -- -D warnings` clean.

**Risk / blocker:**

- LEZ public-testnet endpoint not yet confirmed. Local-only at this phase is
  fine. Public testnet deployment lives in P9.

---

## Phase 3 — Post-proof guest (production-grade)

**Goal:** Promote the P1 spike to a maintained, tested guest with proper
error handling and the final input/output schema.

**Deliverables:**

- `programs/post_proof/` cleaned up and documented.
- `crates/proof-host/` — host-side prover wrapper exposing
  `generate_post_proof(...)` and `verify_post_proof(...)`.
- Unit tests for every failure path (commitment not in tree, invalid epoch,
  malformed share).
- Bench in CI that fails if proof gen exceeds 10s on the standard runner.

**Verify:**

- `cargo test -p proof-host` passes including the negative paths.
- CI bench passes.

**Parallel with:** P2, P4.

---

## Phase 4 — Moderation certificate library

**Goal:** A standalone Rust crate (later wrapped by the TS SDK) that builds,
validates, and aggregates moderator certificates without touching LEZ or
RISC0.

**Deliverables:**

- `crates/moderation-cert/` — pure-Rust, no_std-clean where possible.
- `Certificate` struct: `{ content_id, signers: Vec<(ModeratorPubKey, Sig)>,
  reason: String, share: ShamirShare }`.
- Functions: `sign_vote(...)`, `aggregate_certificate(votes, n_threshold)`,
  `verify_certificate(cert, moderators, n_threshold)`.
- Threshold scheme: **naive ≥N independent Ed25519 signatures** for v1
  (see SPEC open Q #2; this is the spec's working assumption).
- Bounty-required test names: `moderation_cert_construction`,
  `moderation_cert_verification`.

**Verify:**

- All unit tests pass.
- A 5-of-7 example builds, validates, rejects a 4-of-7 set.

**Parallel with:** P2, P3.

**Decision needed before starting:** Confirm naive ≥N Ed25519. If you want
FROST, this phase grows by ~1 week.

---

## Phase 5 — Slash pipeline

**Goal:** End-to-end slash flow: K certs for the same commitment → reconstruct
nullifier secret from accumulated Shamir shares → submit LEZ `Slash` tx →
member's future posts rejected.

**Depends on:** P2 (registry program), P3 (post proof's share scheme), P4
(cert format).

**Deliverables:**

- `crates/slash-evidence/` — collects certificates, reconstructs secret via
  Shamir recovery once K shares are available, packages the slash payload.
- The `Slash` instruction in `programs/membership_registry/` upgraded from
  P2 stub to real verification:
  - Verify reconstructed secret hashes to the commitment
  - Verify all certificates' signatures
  - Verify `certs.len() >= K`
  - Mark member revoked, transfer stake to submitter
- e2e test: register → 3 posts → K certs → reconstruct → slash → 4th post rejected.

**Verify:**

- All four bounty test names pass: `valid_registration`, `valid_post_proof`,
  `strike_accumulation`, `slash_submission`, `post_rejection_after_revocation`.

**Risk:**

- Shamir reconstruction edge cases (duplicate shares from same epoch, wrong
  shares for different content). Plan ~2 days of test-hardening.

---

## Phase 6 — SDK + Waku transport

**Goal:** The `@logos-forum/moderation-sdk` TypeScript package as defined in
SPEC. This is the headline deliverable.

**Deliverables:**

- `sdk/src/index.ts` exporting the API surface sketched in SPEC.
- `sdk/src/transport/` — Waku content-topic encoding, lightPush, Filter, Store
  helpers. ECIES for share-reveal messages, symmetric for moderator-only certs.
- `sdk/src/proofs/` — Node-side bridge to `crates/proof-host` via
  `napi-rs` (or child-process IPC if napi is painful).
- Vitest test suite covering: full lifecycle in a stubbed Waku environment,
  every public function has a happy + failure path.
- `docs/api-reference.md` auto-generated from TSDoc.

**Verify:**

- `pnpm test --filter sdk` ≥90% coverage on public API surface.
- A throwaway script under `scripts/sdk-smoke.ts` exercises the full
  register → post → cert → slash flow using only SDK imports.

**Open question to resolve before starting:** SPEC Q #1 — RISC0 prover
location. Recommend desktop companion. If we go that route, P6 also ships
`crates/proof-daemon/` (a localhost HTTP server the SDK talks to).

---

## Phase 7 — Reference Basecamp forum app

**Goal:** A demo-quality forum that satisfies "usable by a non-technical
user" using only the SDK. Generic styling, no NS branding.

**Deliverables:**

- `app/` Next.js 15 App Router project.
- Pages: instance list, instance detail (post feed), post composer, moderator
  dashboard (sign votes, see pending certs), revoked-members view.
- Forum content type: plain text posts. No comments, no polls, no images —
  scope discipline. The SDK's forum-agnosticism is proven by how minimal the
  app can be while still being usable.
- ESLint custom rule active: any import outside the SDK or core React/Next
  modules fails the build.

**Verify:**

- `pnpm dev` starts the app, manual user-test passes the checklist:
  create instance → register → post → moderate → slash → see rejection.
- Lighthouse score ≥80 on the post feed page (just to avoid embarrassment).
- ESLint rule blocks a test import of `@waku/sdk` directly.

---

## Phase 8 — Docs + IDL (runs in parallel with P5–P7)

**Goal:** All required documentation, generated where possible, hand-written
where needed.

**Deliverables:**

- `docs/protocol.md` (bounty-required):
  - Unlinkability argument with anonymity set size analysis
  - Retroactive deanonymization-on-slash property
  - Moderator trust model
  - Threat model with attacker capabilities
- `docs/api-reference.md` generated from TSDoc.
- `docs/integration-guide.md` — how to build a different forum on the SDK.
- `programs/membership_registry/idl/` — generated IDL using the SPEL framework
  (bounty-required).
- `docs/deployments.md` — testnet program IDs (filled in P9).
- ADRs: ADR-001 (Waku-only), ADR-002 (RISC0 feasibility — P1 output),
  ADR-003 (threshold scheme), ADR-004 (prover location).

**Verify:**

- Every claim in `protocol.md` cross-references either a test or a code path.
- IDL builds and matches the deployed program.

---

## Phase 9 — Demo + deployments + video + submission

**Goal:** Submission-ready artifacts.

**Deliverables:**

- Two forum instances deployed on LEZ public testnet with different K and
  N-of-M parameters. Program IDs in `docs/deployments.md`.
- `scripts/demo.ts` — single-script reproducible end-to-end demo, runs in a
  clean checkout with `RISC0_DEV_MODE=0`.
- README rewritten with copy-pasteable commands.
- Narrated video walkthrough: architecture explanation + full lifecycle demo.
  Terminal visible with `RISC0_DEV_MODE=0`.
- Repo flipped public.
- Submission posted on ns.com.

**Verify:**

- A clean MacBook can clone the repo, run `pnpm install && cargo build
  --release && RISC0_DEV_MODE=0 just demo`, and see the full lifecycle.
- Video uploaded, link in README.

**Prerequisites:**

- LEZ public-testnet endpoint + faucet credentials (the one gap from the LEZ
  inventory above). Action: ask the Logos team in their builder channel.

---

## Parallelism map

| Can be built in parallel | Why |
|---|---|
| P2 + P3 + P4 (after P1) | All three are independent: LEZ program, RISC0 guest, off-chain crate |
| P8 (any time after P5 starts) | Docs follow code; can start as soon as protocol behavior is fixed |
| P9 deployments (any time after P5) | Local testnet deployment can happen well before public testnet |

Sequential bottlenecks: P0 → P1 → (P2 ∥ P3 ∥ P4) → P5 → P6 → P7 → P9.

P8 lifecycle is "start when P5 begins, finish before P9."

---

## Risks and mitigations

| Risk | Probability | Mitigation |
|---|---|---|
| RISC0 can't hit 10s proof gen | **Medium** | P1 spike is explicit gate. Pivot to off-RISC0 circuit if needed. |
| LEZ public testnet not accessible | Low | Reach out to Logos team in P0. Submit as local-only-with-program-IDs if blocked (probably still accepted with explanation). |
| Bounty awarded to another team mid-build | Medium | First-come-first-served. Ship P1 + P2 + P5 fast, even if rough, to show real progress and signal commitment. |
| Threshold-scheme spec drift | Low | Lock in naive Ed25519 in P4 before starting. ADR-003. |
| Waku Store retention loses test forum content | Low | Acceptable — demo regenerates content on every run. |
| One-time cargo build duration eats a workday | High | Run overnight in P0. |

---

## Timeline guess (focused work)

| Phase | Work-days (focused) |
|---|---|
| P0 Foundations | 1.5 |
| P1 Crypto spike | 3 |
| P2 LEZ registry | 3 |
| P3 Post-proof prod | 2 |
| P4 Mod cert lib | 2 |
| P5 Slash pipeline | 3 |
| P6 SDK + Waku | 5 |
| P7 Forum app | 4 |
| P8 Docs + IDL | 3 (runs in parallel, so ~1 calendar day on top) |
| P9 Demo + deploy + video | 3 |
| **Total** | **~25 focused work-days** |

At 4 focused days/week that's ~6 calendar weeks. Matches the earlier estimate.

---

## What I need from you to advance to Phase 3 (Tasks)

1. **Approve this plan** as-is, or push back on phasing / scope.
2. **Resolve the SPEC open questions** that gate specific phases:
   - Q #1 (prover location) — needed before P6
   - Q #2 (threshold scheme) — needed before P4
   - Q #3 (moderator key storage) — needed before P7
   - Q #5 (RLN reuse depth) — needed before P1
3. **Action item:** ping Logos team about public-testnet endpoint + faucet
   (only blocks P9).

Once approved, I expand **Phase 0** into a Phase 3 task breakdown
(`docs/tasks/P0.md`) with discrete checkable steps, then we start executing.
