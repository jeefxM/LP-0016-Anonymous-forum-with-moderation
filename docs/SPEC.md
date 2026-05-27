# Spec: Anonymous Forum Protocol (LP-0016 submission)

> **Status:** Draft v0.1 — not yet approved for implementation.
> **Bounty:** Network School LP-0016, $1,200 USDC, ongoing.
> **Owner:** Davit (denton.gaibo@gmail.com).

---

## Objective

Build a **forum-agnostic moderation SDK** + a **demo-quality reference forum app**
that together satisfy LP-0016: anonymous posting with unlinkability, N-of-M
moderator certificates, and K-strike membership revocation tied to an on-chain
stake.

**Scope is the bounty, nothing more.** The app exists to prove the SDK works
end-to-end and to satisfy the bounty's "working Logos Basecamp app" requirement.
It is **not** a productionised forum, not a Network School product, and not the
successor to forumzero. After submission we decide separately whether to
productize.

The SDK is the primary deliverable. The forum app is a reference implementation
that proves the SDK is genuinely forum-agnostic (we can swap content models
without touching the library).

### Why this exists

Existing "anonymous" forums are pseudonymous: a handle accumulates reputation
and bias contaminates every read. True anonymity means each post is judged on
its content alone — no handle, no history, no linkability. LP-0016 specifies
the cryptographic substrate that makes this compatible with effective
moderation: a coordinated moderator quorum can sanction individual posts, and
sustained sanctions revoke membership and slash the stake — without unmasking
anyone below the revocation threshold.

### Users

- **Members** — post anonymously, accept stake-at-risk in exchange for write
  access.
- **Moderators** — issue certificates against rule-violating content; cannot
  act unilaterally (N-of-M required).
- **Forum operators** — instantiate forum instances with their own K and N-of-M
  parameters.
- **Slashers** — anyone (any wallet) can submit a slash transaction once
  enough certificates accumulate. The slasher claims the stake as reward.

### Success looks like

The first submission that meets every LP-0016 success criterion wins the
bounty. Concrete artifact list lives under **Success Criteria** below.

---

## Tech Stack

| Layer | Choice | Why |
|---|---|---|
| Settlement chain | **LEZ testnet** (Logos Execution Zone) | Required by bounty |
| Smart-contract language | **Rust** + RISC Zero zkVM via `cargo risczero build` | LEZ's native program model |
| ZK proofs | **RISC Zero zkVM 2.x** with `disable-dev-mode` for production | Same toolchain as LEZ programs; proves arbitrary Rust |
| Anonymous-posting primitive | **Semaphore + RLN construction**, re-implemented in RISC0 Rust | We use the cryptographic scheme, not the libraries: no `@semaphore-protocol/*` (EVM/circom) and no Waku RLN package (peer-scoring slash, wrong shape). See ADR-005. |
| Off-chain transport | **Waku** (lightPush + Filter + Store) | The Logos messaging substrate |
| Cert encryption | Waku **ECIES** for share-reveal, **symmetric** for moderator-only certs | Built into `@waku/message-encryption` |
| Library language | **TypeScript** (SDK consumed by web app); Rust crates for proof helpers | App layer is React/Next |
| Forum app | **React + Next.js 15** (Basecamp app) | Standard web stack; built from scratch, **no forumzero code reuse** to keep the SDK clean |
| Storage in app | Waku Store + IndexedDB cache | Waku-only by deliberate choice (see ADR-TBD); Codex out of scope |
| Build orchestration | **pnpm workspaces** + **Cargo workspace** at root | Mixed JS/Rust monorepo |
| Tests | **Vitest** (TS), **`cargo test`** (Rust), end-to-end via `integration_tests/` against local LEZ sequencer | Per bounty: CI must be green |

**Semaphore + RLN clarification:**

- The **Semaphore construction** (commitment in a Merkle tree, ZK proof of
  membership, nullifier for unlinkability) is the spine of our post-proof
  guest. We do **not** import `@semaphore-protocol/*` — those packages target
  EVM/Solidity verifiers via circom, neither of which apply to LEZ/RISC0.
- The **RLN construction** (Shamir-share secret reveal on violation) is how
  we make slashing work. Our violation trigger is "K moderator certificates,"
  not "rate-limit exceeded." Our slash verifier is on LEZ, not Waku's
  peer-scoring system. We do **not** import Waku's RLN package.
- Net: ~150 LOC of Rust in `programs/post_proof/methods/guest/` implementing
  both constructions natively. Deps: `poseidon-rs`, `risc0-zkvm`, `serde`.

---

## Commands

```bash
# Repo root
pnpm install                          # Installs JS workspaces
cargo fetch                           # Fetches Rust deps

# Build
pnpm build                            # Builds SDK + app
cargo build --release                 # Builds host-side helpers
cargo risczero build \
  --manifest-path programs/membership_registry/methods/guest/Cargo.toml
cargo risczero build \
  --manifest-path programs/post_proof/methods/guest/Cargo.toml

# Test
pnpm test                             # SDK + app unit tests
cargo test                            # Rust crates
pnpm test:e2e                         # End-to-end against local sequencer

# Lint / format
pnpm lint                             # ESLint + Prettier
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# Local development
just sequencer                        # Starts LEZ local sequencer + Waku node
pnpm dev                              # Starts Next.js dev server

# Demo (the bounty-required end-to-end script)
RISC0_DEV_MODE=0 just demo            # Full lifecycle: register → post → mod → slash
```

---

## Project Structure

```
forum-protocol/
├── Cargo.toml                          # Cargo workspace root
├── pnpm-workspace.yaml                 # pnpm workspaces
├── package.json
├── Justfile                            # Common dev tasks
├── README.md
│
├── docs/
│   ├── SPEC.md                         # This file
│   ├── protocol.md                     # The bounty-required protocol spec
│   ├── api-reference.md                # SDK API reference
│   ├── integration-guide.md            # How to build a forum on the SDK
│   ├── threat-model.md                 # Trust assumptions, attacker model
│   └── adr/                            # Architecture Decision Records
│
├── programs/                           # LEZ programs (Rust + RISC0 guests)
│   ├── membership_registry/
│   │   ├── core/                       # Shared types (Instruction enum, IDs)
│   │   │   └── src/lib.rs
│   │   └── methods/
│   │       └── guest/                  # The actual RISC0 guest program
│   │           ├── Cargo.toml
│   │           └── src/bin/membership_registry.rs
│   └── post_proof/                     # Standalone post-proof guest
│       └── methods/guest/src/bin/post_proof.rs
│
├── crates/                             # Host-side Rust helpers
│   ├── proof-host/                     # Generates proofs from JS via FFI/WASM
│   ├── slash-evidence/                 # Aggregates certs, reconstructs secret
│   └── lez-runner/                     # Submits register + slash transactions
│
├── sdk/                                # @logos-forum/moderation-sdk (TS)
│   ├── package.json
│   ├── src/
│   │   ├── index.ts                    # Public API surface
│   │   ├── forum.ts                    # createForumInstance / loadForumInstance
│   │   ├── membership.ts               # register / isRevoked
│   │   ├── posting.ts                  # createPostProof / verifyPostProof
│   │   ├── moderation.ts               # signModerationVote / aggregateCertificate
│   │   ├── slashing.ts                 # tryReconstructSlashEvidence / submitSlash
│   │   ├── transport/                  # Waku content-topic + encryption helpers
│   │   ├── proofs/                     # Bindings to RISC0 host crates
│   │   └── types.ts                    # Public types (opaque to consumers)
│   └── tests/
│
├── app/                                # Reference Basecamp forum app (demo-quality)
│   ├── package.json
│   ├── src/app/                        # Next.js 15 App Router
│   ├── src/components/                 # Built fresh — no forumzero imports
│   └── src/lib/                        # ONLY imports from `@logos-forum/moderation-sdk`
│
├── scripts/
│   ├── deploy-program.ts               # Deploys LEZ programs via wallet CLI
│   ├── create-forum-instance.ts        # Bounty-required: 2 instances on LEZ testnet
│   └── demo.ts                         # Bounty-required: end-to-end demo script
│
└── integration_tests/                  # End-to-end against local sequencer
    ├── configs/
    └── tests/
```

**Hard rule:** files inside `app/src/` may import **only** from
`@logos-forum/moderation-sdk` and standard React/Next packages — never from
`crates/`, `programs/`, `@waku/*`, `risc0-*` directly. Enforced by a custom
ESLint rule (`no-direct-protocol-imports`). This is what makes
"forum-agnostic" demonstrable to the reviewer.

---

## Code Style

### SDK (TypeScript)

```typescript
// sdk/src/posting.ts
import { commitment, type Commitment } from "./types";
import { generatePostProof } from "./proofs";
import { encodePostEnvelope } from "./transport";

/**
 * Generates an anonymous post envelope. The envelope contains a zero-knowledge
 * proof that the caller is a registered, non-revoked member of `forum`, along
 * with a Shamir share of the caller's nullifier secret bound to `contentId`
 * and `epoch`. Two envelopes from the same member in the same epoch reveal
 * enough shares to reconstruct the secret — that property is what makes
 * slashing possible after K moderation certificates are issued.
 *
 * The library makes no assumption about what `contentId` represents. Forum
 * apps choose their own content hash scheme (text post hash, image CID, etc).
 */
export async function createPostProof(params: {
  forum: ForumInstance;
  identitySecret: Uint8Array;
  contentId: ContentId;
  epoch: number;
}): Promise<PostEnvelope> {
  const memberCommitment = commitment(params.identitySecret);
  if (await isRevoked(params.forum, memberCommitment)) {
    throw new ForumError("revoked", `member ${memberCommitment} is revoked`);
  }

  const proof = await generatePostProof({
    secret: params.identitySecret,
    contentId: params.contentId,
    epoch: params.epoch,
    treeRoot: params.forum.treeRoot,
  });

  return encodePostEnvelope({
    proof,
    contentId: params.contentId,
    epoch: params.epoch,
    nullifierShare: proof.nullifierShare,
  });
}
```

**Key conventions:**

- Public API takes `params: { ... }` objects, never positional args (forces named clarity).
- All errors are typed instances of `ForumError` with a discriminant `kind`.
- No `any`. No `as` casts outside `transport/` boundary code.
- Async-only — sync APIs are a smell for crypto-heavy code.
- File-level docstrings on every `sdk/src/*.ts` file explaining what the module owns.

### Rust (programs + crates)

```rust
// programs/membership_registry/methods/guest/src/bin/membership_registry.rs
#![no_main]
#![no_std]

use nssa_core::program::AccountPostState;
use risc0_zkvm::guest::entry;
use membership_registry_core::{Instruction, RegistryState};

entry!(main);

fn main() {
    let (input, instruction_data) = read_nssa_inputs::<Instruction>();
    let pre = input.pre_states;

    let post = match input.instruction {
        Instruction::Register { commitment, stake_amount } => {
            handle_register(pre, commitment, stake_amount)
        }
        Instruction::Slash { commitment, reconstructed_secret, certificates } => {
            handle_slash(pre, commitment, reconstructed_secret, &certificates)
        }
    };

    write_nssa_outputs(instruction_data, pre, post);
}
```

**Key conventions:**

- `#![no_std]` on all RISC0 guests.
- `panic!` is the only failure mode inside guests (RISC0 surfaces it as
  `ProgramExecutionFailed`).
- Instruction enums + state types live in a separate `*_core` crate so the
  host side can import them without pulling RISC0 deps.
- `cargo clippy -- -D warnings` is CI-blocking. No `unwrap()` outside tests.

---

## Testing Strategy

| Test level | Framework | Lives in | Runs in CI |
|---|---|---|---|
| SDK unit | Vitest | `sdk/tests/` | Yes |
| Rust unit | `cargo test` | inline `#[cfg(test)]` | Yes |
| LEZ guest tests | RISC0 dev mode | `programs/*/tests/` | Yes (fast, dev mode OK) |
| Cross-language e2e | Vitest + spawned sequencer | `integration_tests/` | Yes (`RISC0_DEV_MODE=0`) |
| Manual demo | The `just demo` script | `scripts/demo.ts` | Recorded once for video |

**Coverage targets:**

- SDK: 90% line coverage on public API surface, 70% overall.
- Rust crates: every public function has at least one test.
- Guests: every instruction variant has a happy-path test + at least one
  failure-mode test (e.g. register-with-insufficient-stake, slash-with-K-1-certs).

**Bounty-required tests** (must exist by name in the suite):

- `valid_registration`
- `valid_post_proof`
- `moderation_cert_construction`
- `moderation_cert_verification`
- `strike_accumulation`
- `slash_submission`
- `post_rejection_after_revocation`

These line up with the LP-0016 acceptance criteria — putting them at named
test functions makes review trivial.

---

## Boundaries

### Always

- Run `pnpm lint && cargo clippy && pnpm test && cargo test` before every commit.
- Update `docs/SPEC.md` and `docs/protocol.md` when behavior changes — spec
  drift is the most likely reason a reviewer rejects.
- Keep `app/src/` free of any direct protocol-layer imports (lint-enforced).
- Use `risc0-zkvm = { features = ["disable-dev-mode"] }` in any binary that
  ships to testnet.
- Pin Rust toolchain to whatever `lez/rust-toolchain.toml` specifies.

### Ask first

- Adding a new Waku content-topic — affects on-the-wire compatibility.
- Adding a new LEZ instruction variant — affects deployed program ID.
- Changing the moderator certificate format — invalidates outstanding certs.
- Adding new top-level dependencies (especially crypto crates).
- Choosing a threshold-signature scheme (FROST vs BLS vs naive multi-sig) —
  this is a load-bearing decision worth ADR review.

### Never

- Commit private keys, mnemonics, or wallet files.
- Skip `RISC0_DEV_MODE=0` in the recorded demo or in deployed binaries.
- Modify the SDK from inside the app to "make something work" — that's an
  instant fail on the bounty's "library must work without modification" rule.
- Add forum-specific types (`Thread`, `Comment`, `Post`) to the SDK.
- Use `--no-verify` to bypass pre-commit hooks.

---

## Success Criteria

Each item below is a binary pass/fail check the bounty reviewer can run.

### Functionality

- [ ] A member can register on an instance with stake, then publish posts that
      carry valid anonymous proofs of membership.
- [ ] Two posts from the same member are unlinkable to any observer, including
      moderators, while the member is below K strikes.
- [ ] After K strikes accumulate, the reconstructed secret enables retroactive
      linking of that member's prior posts. **No other member's anonymity is
      affected** — proven by test.
- [ ] N-of-M moderators can jointly produce a valid certificate off-chain.
      Fewer than N cannot.
- [ ] Once K certs are accumulated for one member, any wallet can submit a
      slash transaction that the LEZ registry accepts and processes.
- [ ] After slash, a post with the slashed commitment is rejected by
      `verifyPostProof`.
- [ ] K and N-of-M are per-instance parameters. We deploy two instances on LEZ
      testnet with different values to demonstrate.

### Usability

- [ ] SDK exposes a documented public API (every public symbol has a doc
      comment, full reference in `docs/api-reference.md`).
- [ ] An IDL for the membership registry LEZ program is generated and
      committed under `programs/membership_registry/idl/`.
- [ ] The Basecamp app is usable by a non-technical user. No CLI required for
      register / post / moderate / view history. Manual user-test before
      submission.

### Reliability

- [ ] Proof generation failure surfaces a typed error and allows retry without
      consuming the member's nullifier.
- [ ] Partial certificates (< N votes) cannot be submitted on-chain. Enforced
      client-side in the SDK.
- [ ] Pending posts and mod actions are queued and retried on transient Waku
      or sequencer failure.

### Performance

- [ ] ZK membership proof generation < 10s on a MacBook Pro M-series.
      Benchmarked in CI on a comparable runner.
- [ ] CU cost of register + slash documented in `docs/protocol.md` against the
      current LEZ testnet compute budget.

### Supportability

- [ ] Registry program deployed and tested on LEZ devnet/testnet. Program ID
      committed to `docs/deployments.md`.
- [ ] End-to-end integration tests run against a local LEZ sequencer in CI.
- [ ] Default branch is green.
- [ ] README documents deploy → register → post → moderate → slash steps with
      copy-pasteable commands.
- [ ] `just demo` succeeds in a clean checkout with `RISC0_DEV_MODE=0`.
- [ ] A narrated video walkthrough is recorded showing architecture, key
      decisions, and the full lifecycle. Terminal visible with
      `RISC0_DEV_MODE=0` set.

### Submission

- [ ] Public GitHub repo under MIT license.
- [ ] Two live forum instances deployed on LEZ testnet with verified program
      IDs in `docs/deployments.md`.
- [ ] `docs/protocol.md` covers: unlinkability argument, anonymity set size
      analysis, retroactive deanonymization-on-slash property, moderator trust
      model, full threat model.
- [ ] Submission posted to the LP-0016 page on ns.com.

---

## Open Questions

These need resolution before Phase 2 (Plan).

1. ~~RISC0 host calls from the browser.~~ **Resolved:** desktop companion
   daemon. The SDK spawns a localhost prover binary (`crates/proof-daemon/`)
   that the browser talks to over HTTP. ADR-004 records the choice.

2. ~~Threshold signature scheme.~~ **Resolved:** naive ≥N independent Ed25519
   signatures. Smaller crypto surface for v1. FROST is a v2 upgrade path.
   ADR-003 records the choice.

3. ~~Moderator key storage.~~ **Resolved:** password-encrypted software key,
   loaded into the Basecamp app at session start. No hardware-wallet support
   in v1. ADR-006 will record details.

4. ~~Forum content storage durability.~~ **Resolved:** Waku Store only.
   Codex is out of scope for the bounty deliverable. The demo app shows a
   small banner noting content retention follows the Waku Store window.
   ADR-001 will record this choice.

5. ~~RLN reuse depth.~~ **Resolved:** rebuild the Semaphore + RLN
   construction natively in RISC0 Rust. Waku's RLN is a design reference, not
   a dependency. Same call applies to Semaphore JS libraries. ADR-005 records
   the choice.

6. **Repo public from day 1?** Bounty requires "public repository" at
   submission, not before. Recommend private during v1 build, flipped public
   ~2 weeks before submission to leave room for last-minute fixes.

---

## Out of Scope (explicit)

Per the bounty's "Out of Scope" section, we do not build:

- Discovery, search, feeds, or social graph features
- Reputation tiers or rate-limits on posting frequency
- Cross-forum identity linking or cross-forum revocation
- End-to-end encryption of forum content (the SDK may support it, the app
  doesn't require it)
- Hosted infrastructure beyond running the Basecamp app

And for our v1 specifically:

- Mainnet deployment
- Codex storage integration
- Mobile-native app (web is responsive but no React Native)
- Multi-language UI (English only)
- Any productization for Network School, forumzero, or other downstream use
- Reusing forumzero code, components, or branding in the demo app
- Migration tooling from forumzero's Arkiv data — forumzero is a separate
  product on a separate stack; touching it is a post-bounty decision
