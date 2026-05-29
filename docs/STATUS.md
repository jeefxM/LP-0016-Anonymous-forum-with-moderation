# STATUS — read this first to resume

Last updated: 2026-05-28. This is the authoritative "where are we, what's
next" snapshot. Static design lives in `SPEC.md` / `PLAN.md`; decisions in
`adr/`; this file is the live state.

## What this project is

LP-0016 submission: a forum-agnostic SDK + reference app for anonymous
posting, N-of-M threshold moderation, and K-strike membership revocation
on the Logos stack (LEZ + Waku). Bounty scope only — not a productionised
forum (see ADR-001, SPEC "Objective").

## TL;DR state

**The entire cryptographic protocol is complete and chain-verified.**
register → post → moderate → slash → revoke runs end-to-end on a live LEZ
chain. ~14–15 of 25 planned work-days in. Everything cryptographically
novel is done; the rest is packaging with no remaining crypto unknowns.

## Phase status

| Phase | State |
|---|---|
| P0 Foundations | ✅ done |
| P1 Crypto spike (RISC0 feasibility) | ✅ done (conditional — see perf gate below) |
| P2 LEZ registry program | ✅ done; **Register live on-chain** |
| P3 post_proof productionised | ✅ done |
| P4 moderation-cert library | ✅ done |
| P5 Slash pipeline | ✅ done; **Slash live on-chain** |
| P5.6 on-chain verify_slash (ADR-008) | ✅ done; ark-bn254+ed25519 run inside the zkVM |
| P5.2 post_proof emits real Shamir share | ✅ done |
| **P6 SDK + Waku** | ✅ done |
| ↳ P6.1 SDK public API surface | ✅ done (`sdk/src/{types,index}.ts`, typechecks) |
| ↳ P6.2 proof-daemon (Rust HTTP) | ✅ done; **11/12 endpoints smoke-verified on live chain (dev + real mode); slash/submit library-verified** |
| ↳ P6.3 SDK client → daemon | ✅ done; **full lifecycle verified live via SDK imports** |
| ↳ P6.4 Waku transport (js-waku) | ✅ done; **live round-trip verified against nwaku** |
| ↳ P6.5 SDK smoke test | ✅ done; **full lifecycle (register→post→moderate→slash→revoke) green via SDK imports against daemon + nwaku + chain** (`sdk/tests/lifecycle.mjs`) |
| P7 Reference Basecamp app | ⬜ not started |
| P8 Docs + IDL (SPEL) | ⬜ not started |
| P9 Demo + testnet deploy + video | ⬜ not started |

## Test tally (all green)

post_proof_core 12 · moderation-cert 8 · membership_registry_core 11 ·
slash-evidence 10 = **41 tests**. Plus Register + full Slash proven on a
live chain via `crates/lez-runner` (`forum_register`, `forum_slash`).

Bounty-named tests: 6 of 7 at logic layer (`valid_registration`,
`moderation_cert_construction`, `moderation_cert_verification`,
`strike_accumulation`, `slash_submission`,
`post_rejection_after_revocation`). The 7th, `valid_post_proof`, is
satisfied by `bench_post_proof` (real receipt verifies) but not yet a
named `#[test]` — see loose ends.

### P6.4 as built so far (Waku transport)

Decisions in **ADR-009** (symmetric-only encryption; ECIES deferred — no SDK
consumer; certs looked up by **nullifier**, not commitment; daemon stays
tree-stateless). Delivered:
- `sdk/src/transport.ts` — the only `@waku/*` importer. Node lifecycle
  (`createLightNode` + dial static nwaku), per-forum content topics
  (reg/post/cert), symmetric posts+certs / plaintext registrations, and pure
  helpers `selectCertsForNullifier` + `RegistrationSync` (leafIndex-ordered,
  gap-buffering, idempotent tree sync).
- SDK surface (additive to P6.1): `publishPost`, `subscribePosts`,
  `publishCertificate`, `listCertificatesByNullifier`,
  `subscribeRegistrations`; `register` now announces its leaf; the slash path
  is rekeyed to nullifier (`tryReconstructSlashEvidence(forum, nullifier)`
  → daemon `/v1/slash/recover` → fill Merkle path from `config.tree`).
- Daemon `/v1/slash/recover` (slash-evidence `recover_commitment`, rebuilt on
  Hetzner). `SdkConfig.transport?: WakuTransport`.
- **Dependency fix:** pinned `@multiformats/multiaddr@^12` via a pnpm
  override — `@waku/enr@0.0.33` needs the v12 `./convert` subpath that v13
  removed. Without it `@waku/sdk` won't even import. Clean reinstall applied.
- Verified: 20 vitest tests (incl. transport join/ordering) + `tsc` clean.
- **Live-verified** against a local nwaku (`sdk/tests/waku-integration.mjs`,
  run ON Hetzner — no tunnel): Filter delivery, Store `listCertificatesBy
  Nullifier` join, and ordered registration tree-sync all green.
  - nwaku run (cluster 2, autosharding 8, **websocket-support**, no RLN):
    `docker run -d --name nwaku -p127.0.0.1:60000:60000 -p127.0.0.1:8000:8000
    -p127.0.0.1:8645:8645 wakuorg/nwaku:latest --tcp-port=60000
    --websocket-support=true --websocket-port=8000 --rest=true
    --rest-address=0.0.0.0 --relay --lightpush --filter --store --cluster-id=2
    --num-shards-in-network=8 --shard=0..7 --nat=extip:127.0.0.1`
  - Gotchas (now handled in code): a Node light node has **no TCP transport**
    and its websockets default to **wss-only** — must dial a `/ws` multiaddr
    AND override libp2p with `webSockets({ filter: all })` (see
    `transport.ts`). Cluster 1 forces RLN (hangs without an eth RPC) — use a
    non-TWN cluster for local tests.

## DONE: perf gate — membership proof → Groth16 (ADR-010)

The `<10s` bounty criterion is **not** met by the risc0 zkVM membership
proof (55–65s CPU) and **cannot be**: risc0 3.0.5 has no Metal backend
(ADR-002 update), and a laptop has no CUDA. The bounty actually points to a
**Semaphore/RLN circuit** for this proof (it calls it a "circuit"; posts are
off-chain so the proof is verified off-chain, decoupled from LEZ). So the
risc0 `post_proof` was replaced with a **Groth16 circuit** (ADR-010,
decision 1b: keep the SHA-256 stack, only the off-chain prover/verifier
changed). The risc0 LEZ register/slash program is unaffected, and the
circuit's emitted shares still satisfy the unchanged on-chain `verify_slash`
(proven by the live slash in `lifecycle.mjs`).

Tasks PERF-1..6 — **all done, live-verified**:
- ✅ PERF-1 ADR-010 spec (byte-exact preimages + scope guard).
- ✅ PERF-2 circom 2.2.3 installed; **pre-flight PASSED** — circomlib SHA-256
  over `"node"‖l‖r` is bit-identical to Rust sha2 (MSB-first bit order, 2-block
  preimage confirmed). One node hash ≈ 62k constraints → full circuit ~1M →
  rapidsnark required. See `circuits/preflight_*`.
- ✅ PERF-3 `circuits/membership.circom` — **1.14M constraints, outputs match
  Rust byte-for-byte** (nullifier/shareX/shareY via `circuit_oracle` +
  `validate.mjs`; Merkle-root constraint satisfied; mod-r field-LC trick
  confirmed). Compiled K=3.
- ✅ PERF-4 ptau (2^21, zkevm bucket — hermez S3 is dead) + `groth16 setup`
  on Hetzner → `membership_0.zkey` (678MB) + `vkey.json` (committed). Skipped
  the optional `contribute` (demo-grade ceremony); ptau deleted after.
- ✅ PERF-5 **daemon wired to Groth16 + <10s GATE MET on the live path**:
  `/v1/post/prove` now builds the circuit input, runs node witness-gen +
  rapidsnark `prover`, and returns the Groth16 proof + public signals as the
  `PostEnvelope.receipt` (`base64(JSON {proof, publicSignals})`, ~2KB). End to
  end over HTTP: **4.63s** (status 200), outputs match the oracle byte-for-byte.
  ~12× faster than the 55–65s risc0 zkVM. Witness is laptop-equivalent (2.4s
  M2). rapidsnark built on Hetzner (Linux); native-Mac build is a polish item
  (cmake-4/arm64 quirks).
- ✅ PERF-6 daemon `/v1/post/verify` → snarkjs Groth16 verify **+ a
  load-bearing bind check** (public signals must equal the envelope's
  nullifier/shareX/shareY/treeRoot/epoch/contentId byte-for-byte, else a valid
  proof could be replayed against a different context) + the existing on-chain
  stale-root check. `lifecycle.mjs` is **green end-to-end** (register → 3
  Groth16 posts → verify → moderate → slash → revoke) against the live daemon
  + nwaku + chain.

Toolchain: circom 2.2.3 (`~/.cargo/bin/circom`), snarkjs 0.7.6 (global on
Hetzner), rapidsnark `prover` at `~/rapidsnark/build_prover/src/prover`. The
risc0 `post_proof` guest is now legacy (kept for history; off the live path).
This was the last hard technical item; everything else (P7 app, P8 docs,
P9 demo/testnet) is packaging.

## Staking (ADR-011) — done (verified via V03State e2e)

"Register with a stake" / slash "claims the stake" is implemented and proven
end-to-end against the LEZ execution engine.

- ✅ Design: **ADR-011** (registry-owned escrow PDA; member funds it via
  `authenticated_transfer.Transfer(member → escrow)`; Slash direct-debits
  `escrow → slasher` since the registry owns the escrow).
- ✅ Core primitives: `staking::{AuthTransferInstruction, escrow_seed}` in
  `membership_registry_core` (vendored enum, tested).
- ✅ Guest: `Initialize` claims the escrow PDA, `Register` requires the escrow
  to hold `stake_amount` per member (rejects a substituted escrow), `Slash`
  pays `stake_amount` to the slasher. **ImageID
  `7c4caee9cb41073b0bae27c5fce0cf74a42136604a01da07051066dfb5769259`**.
  Supersedes the old `6eca79ea…` registry ImageID.
- ✅ `lez-runner`: `initialize`/`register`/`slash` reshaped to multi-account
  (state + escrow + slasher); generalized signed/no-auth submit; standalone
  funding helpers. **Initialize verified live** on the Hetzner sequencer
  (escrow PDA claimed by the registry) after a `deploy-program` tx.
- ✅ **e2e proof**: `crates/lez-runner/tests/staking_lifecycle.rs`
  (`valid_staking_lifecycle`) runs the full path in-process via `nssa::V03State`
  (real risc0 execution of the deployed guest): Initialize → member-signed
  stake into escrow (owner preserved = registry) → Register stake-check →
  K strikes → Slash drains escrow to slasher + revokes member. Run with
  `RISC0_DEV_MODE=1 cargo test --release --test staking_lifecycle`.

Findings that shaped this (see ADR-011 "Build outcome"):
- The guest needs an explicit `deploy-program` tx; it is not implicit.
- **The LEZ faucet is genesis-only** (user faucet txs are dropped by design —
  LEZ's `cannot_execute_faucet_program` test), so there is no runtime funding
  on the local single-node chain → the e2e is the in-process V03State test.
- The slasher must be an existing (non-default) account.

⬜ Follow-ups (not blocking the staking proof):
- **daemon DTOs/handlers + SDK** to thread escrow/slasher/funding so the app
  path stakes too (lower priority).
- **public testnet run** — see the SPEL port below (it's the vehicle).

## SPEL port (ADR-012) — in progress

Porting the on-chain program to `spel-framework` on the current LEZ to unblock
**IDL via SPEL** + the **live testnet**. The crypto protocol (core, circuits,
certs, slash-evidence, daemon, SDK, app) carries over unchanged; only the guest
`main` is re-expressed as a `#[lez_program]` module + `lez-runner` → SPEL CLI.

- ✅ **Version pinned**: the current LEZ is `logos-execution-zone` tag
  **`v0.2.0-rc3` (cf3639d8)** (what `spel-framework` v0.4.0 / `logos-co/spel`
  HEAD `d24dbaa` pins, and almost certainly what `testnet.lez.logos.co` runs —
  its faucet wants **BN254 Fr** account keys, vs secp256k1 on our old
  `8c8f5b57`). Earlier the multisig reference pinned `lssa@767b5afd`; the
  current SPEL release uses `v0.2.0-rc3`.
- ✅ **Toolchain validated on Hetzner**: Rust 1.94 + cargo-risczero 3.0.5 +
  `spel` CLI (installed from `logos-co/spel`). A `spel init` scaffold passed
  both `make idl` and `make build` against `nssa_core@v0.2.0-rc3`.
- ✅ **Project ported** (`programs/registry-spel/`): the guest is a
  `#[lez_program]` module — Initialize/Register/Slash as `#[instruction]`
  handlers with `#[account]` PDA attrs (state ← `arg("seed")`, registry-owned
  escrow ← `account("state")`, slasher), all calling `membership_registry_core`
  (vendored into the project — the risc0 docker context can't reach the outer
  crate). Builds clean → **ImageID
  `353c847815d363bbf51b72753c77ad8800e6f83e515211c7d8ef964546dd9887`**.
- ✅ **IDL via SPEL**: `make idl` → `registry-spel-idl.json` with the full
  instruction/account/PDA-seed layout. (Custom arg types like `ForumConfig`
  are referenced by name; expanding their definitions needs `#[account_type]`
  annotations — a later refinement; not required for the deliverable.)
- ✅ **DEPLOYED LIVE to `testnet.lez.logos.co`**. Built the v0.2.0-rc3 `wallet`,
  `check-health` **confirmed our builtin program versions match the testnet**.
  Size-optimized the guest (672KB → **341KB**, under the ~512KB deploy cap) and
  `wallet deploy-program` succeeded (deploy exit 0). Live ImageID
  `69373bb59ef0468f8f8748229d79f7cf54ca08b954bef983c641dcedd6d91d47`.
- ✅ **Funding solved without the faucet**: the testnet wallet ships
  preconfigured, wallet-controlled genesis-funded accounts
  (`6iArKUXx…`=10000, `7wHg9sb…`=20000, auth-transfer-owned → spendable). The
  `logosblocks` faucet is the *bedrock* layer (BN254 `recipient_pk`), not LEZ —
  not needed. Wallet at `~/wallet-testnet` (password `forum-protocol-dev`).
- ✅ **LIVE register-with-stake on the testnet** (program-id `4766fcc2…`,
  seed `0x22..22`, state PDA `A5tj58u7…`, escrow PDA `CDn2DHcv…`):
  - `initialize` — tx `4cd0e4e7…`, confirmed; state holds `ForumState`
    (k=3, n=2, stake=1000), escrow claimed by the registry (balance 0).
  - fund escrow `auth-transfer` 1000 from preconfigured `6iArKUXx…` → escrow
    now balance 1000, **owner still the registry** (credit-preserves-owner
    proven live, ADR-011 lynchpin).
  - `register` — tx `6b5b359d…`; state advanced `next_leaf_index 0→1` and
    `tree_root 34fc00e4… → f47cfa82…` (stake-check passed, member admitted).
  - Arg encoding: `initialize`/`register` use IDL-native flat args (the SPEL
    CLI can't build undefined struct args; `#[account_type]` is for
    account-data types, not instruction args). The CLI also needs `--state`
    explicitly for the `account("state")`-derived escrow PDA.
  - Note: the v0.2.0-rc3 wallet's confirmation poll (5 blocks) is shorter than
    the testnet's cadence, so txs report "not found in N blocks" but still
    land — verify by reading the account, not the poll result.
- ⬜ Live **slash** on testnet — its cert vector (`Vec<ModerationCertificateWire>`)
  is complex to encode through the CLI; slash is proven via the V03State e2e
  (full lifecycle). Could flatten later for a live slash too.
- ⬜ Two live instances with different K/N-of-M (+ a K=2 circuit).

## Next after the perf gate (P7)

P6 is complete and live-verified end to end. Next is **P7**: the reference
Basecamp app (Next.js, `app/`) that imports ONLY `@logos-forum/moderation-sdk`
— register/post/moderate/view, plus the Waku Store-window banner (ADR-001).
`sdk/tests/lifecycle.mjs` is the working reference for the full SDK flow.
Then P8 (docs incl. the required `protocol.md` + IDL) and P9 (demo + two live
instances + video). Note `app/` still has no tsconfig — root `tsc -b` won't
pass until P7 scaffolds it.

### P6.4 reference (Waku transport)

P6.2 + P6.3 are done (see below). Build the Waku transport (`sdk/src`, pure
TS via js-waku): publish/subscribe post envelopes + moderation certificates,
and feed the SDK's `MerkleTree` (config.tree) from the commitments seen on
Waku so multi-member trees stay in sync (today the SDK only appends its own
registrations). This unblocks the three Waku-stubbed SDK functions
(`publishCertificate`, `listCertificatesForMember`, and therefore
`tryReconstructSlashEvidence`). Contract = `sdk/src/types.ts`.

### P6.3 as built (SDK client)

`sdk/src/` now implements the P6.1 surface for real:
- `tree.ts` — `MerkleTree` (depth 16, commitment-as-leaf, vendored sync
  SHA-256). Matches Rust `fold_path` exactly; the empty root equals the
  live-chain `empty_tree_root` (34fc..431d44) — asserted in tests.
- `client.ts` — `daemonPost` with daemon `{kind,message}` → typed
  `ForumError` mapping (+ `daemon_unreachable` on network failure).
- `index.ts` — all functions wired to the daemon. `register` /
  `createPostProof` derive Merkle paths from `config.tree` (ADR-004) and
  guard that `tree.root() === forum.treeRoot`. The 3 Waku-dependent
  functions throw `transport_error` pointing at P6.4.

Verification: 14 vitest unit tests (tree vectors + client error mapping);
`tsc -p tsconfig.json` clean; and `sdk/tests/integration.mjs` drives the
full register → post → verify → moderate flow through SDK imports against
the live daemon (SSH-tunnel localhost:8787 → Hetzner) — all green.

ESM note: relative imports in `sdk/src` use explicit `.js` extensions so the
emitted `dist/` runs under Node ESM (`"type": "module"`).

### P6.2 as built (proof-daemon)

`crates/proof-daemon` is an axum localhost server (default 127.0.0.1:8787),
excluded from the Mac workspace, built on Hetzner. ADR-004 governs it. It
holds no tree state; callers pass Merkle paths; it re-queries the PDA per
call. Endpoint → SDK-function map (all POST, JSON; 32/64-byte fields hex,
receipt base64, u128 as decimal string):

- pure crypto: `/v1/identity/create`, `/v1/moderation/sign`,
  `/v1/moderation/aggregate`
- chain: `/v1/forum/create`, `/v1/forum/load`, `/v1/member/register`,
  `/v1/member/is-revoked`, `/v1/slash/reconstruct`, `/v1/slash/submit`
- proving: `/v1/post/prove`, `/v1/post/verify`
- `/v1/health`

`publishCertificate` / `listCertificatesForMember` are deliberately NOT in
the daemon — they're Waku (P6.4). Chain helpers were extracted into
`crates/lez-runner/src/lib.rs` (the two runner bins are now thin wrappers).
Proving helpers are in `crates/proof-host/src/lib.rs`. Smoke script:
`crates/proof-daemon/smoke.sh` (needs `jq`).

Run on Hetzner (post-PERF: Groth16 prover, not risc0 — needs CIRCUIT_DIR +
the rapidsnark prover; `RISC0_DEV_MODE=1` is still set for the register/slash
*chain* proofs via lez-runner, which match the dev-mode sequencer):
```
tmux new-session -d -s daemon "cd ~/forum-protocol/crates/proof-daemon && \
NSSA_WALLET_HOME_DIR=~/lez/wallet/configs/debug \
MEMBERSHIP_REGISTRY_BIN=~/forum-protocol/programs/membership_registry/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/membership_registry.bin \
CIRCUIT_DIR=~/circuits \
RAPIDSNARK_PROVER=~/rapidsnark/build_prover/src/prover \
RISC0_DEV_MODE=1 ./target/release/proof-daemon > ~/daemon.log 2>&1"
```
(snarkjs must be on PATH for `/v1/post/verify`; `npm i -g snarkjs`.)

## Loose ends / backlog (these were tracked as in-session tasks)

- **P6.2 follow-ups (new):**
  - **`verifyPostProof` cannot check revocation.** A post envelope is
    anonymous (nullifier + shares, no commitment), so the daemon's
    `/v1/post/verify` checks only: receipt valid + committed root == claimed
    root == current on-chain root. Revocation enforcement at post time
    needs root rotation or a non-membership proof — a real protocol
    decision for `docs/protocol.md` (P8). The SDK doc comment in
    `sdk/src/index.ts` still claims a revoked check; reconcile it in P8.
  - **`txHash` is `format!("{:?}")` of the sequencer's `HashType`** (in
    `lez-runner::submit`). Works as an opaque id; if a canonical hex hash is
    wanted, find HashType's Display/hex impl and use it.
  - **`createForum` polls `|_| true`** (returns first decodable state). On
    an already-initialised PDA it returns current state rather than erroring
    — acceptable for v1, revisit if create-idempotency matters.
  - **Daemon wallet unlock is boot-time env only** (NSSA_WALLET_HOME_DIR).
    An `/unlock` endpoint is a P6.5/P7 item (ADR-006).
  - **`jq` is now a smoke-test dependency** (installed on Hetzner). Note for
    CI / a fresh box. `smoke.sh` pipes bodies via stdin (`--data-binary @-`)
    because real-mode receipts (multi-MB) overflow a curl `-d` arg / ARG_MAX.
  - **`/v1/slash/submit` is verified at the library layer** (via the
    `forum_slash` runner bin) but its HTTP path (DTO→`to_wire`→submit→poll)
    was not exercised end-to-end in the smoke. Low risk (only the DTO
    conversion is new), but exercise it when P6.5 does the full SDK lifecycle.
  - **Verified:** 11 of 12 endpoints smoke-passed on the live chain in both
    `RISC0_DEV_MODE=1` and `=0`; real-mode prove (~55s) → verify round-trips
    a multi-MB receipt OK after raising axum's body limit to 16 MB.


- **#43 Pre-P9: trim post_proof to one RISC0 segment.** Real Shamir pushed
  it to 2 segments (524288 cycles, 54.87s on Hetzner CPU). Trim ~30k user
  cycles (fewer ark-bn254 modular reductions / reuse reduced secret Fr /
  TREE_DEPTH 16→12) to get back under 262144 = ~27s. See ADR-002 update.
- **#16 Pre-P9: re-bench post_proof on M-series Metal.** The decisive perf
  gate. Target <10s. risc0-zkvm `metal` feature. If (#43)+Metal still
  misses, escalate to Bonsai or off-RISC0 circuit (ADR-002 alternatives).
- **P5.5: add `valid_post_proof` as a named `#[test]`** wrapping the
  bench_post_proof prove+verify (mark `#[ignore]` for CI — ~30s).
- **#13 P8: locate the SPEL framework** for the membership-registry IDL
  (bounty Usability requirement). Not in the LEZ repo; it's a separate
  Logos-team artifact. Ask in their builder channel / find the repo.
- **#14: find LP-0001 (Private NFT) + LP-0003 (Private Allowlist) winning
  repos** for reference patterns. Nice-to-have.
- **Public LEZ testnet endpoint + faucet** — needed for P9's "two live
  instances." Not yet obtained; ask the Logos team.

### Docs & housekeeping loose ends

- **Unwritten ADRs.** `adr/README.md` indexes several decisions that are
  made-and-applied in code but not yet written up as ADR files:
  - ADR-004 (prover location = localhost daemon) — finalise during P6.2.
  - ADR-005 (re-implement Semaphore+RLN natively; SHA-256 leaf hashing for
    RISC0 perf, not Poseidon) — decision is live in the guests; write it up.
  - ADR-006 (moderator key storage = password-encrypted software key) —
    finalise during P7.
- **CI workflow is stale.** `.github/workflows/ci.yml` was written in P0
  against empty crates. It has never run against the real crates and the
  guest builds (which need Hetzner + docker + ruint pin) aren't represented.
  Revisit before relying on CI; the bounty requires "CI green on default
  branch," so this needs real work in P8/P9.
- **`pnpm lint` uses `tsc`, not biome.** Biome 1.9.4/2.4.16 segfaults on
  this macOS (Darwin 25). Lint is `tsc -b --noEmit` for now. Revisit when
  biome ships a working Darwin-25 binary, or pick another formatter.
- **api-reference.md not generated.** The SDK's public API (sdk/src) has
  full TSDoc; P8 should generate docs/api-reference.md from it (bounty
  Usability requirement: "documented API").
- **docs/protocol.md not written** — the bounty REQUIRES it (unlinkability
  argument, anonymity-set analysis, retroactive-deanon-on-slash property,
  moderator trust model, threat model). This is a hard P8 deliverable, not
  optional. The material exists across ADR-002/003/008 + SPEC; needs
  assembling into the required doc.

## Environment (CRITICAL — don't rediscover this)

Everything chain/proof-related builds and runs on the **Hetzner box**
(`ssh hetzner`, x86_64 Ubuntu, 16 core / 30GB). The Mac can't
`cargo risczero build` (Apple-Silicon docker fails on the x86 guest-builder
image). Full recipe: **`docs/dev/local-sequencer.md`**. Key facts:

- LEZ checkout at `~/lez`, pinned rev `8c8f5b57` (matches `nssa_core` git
  dep, ADR-007). forum-protocol at `~/forum-protocol`.
- Live chain runs in tmux: session `bedrock` (docker, :8080) + session
  `seq` (`sequencer_service`, :3040, RISC0_DEV_MODE=1). Restart cmds in
  `deployments.md`. They may have stopped — check `ssh hetzner 'tmux ls'`.
- Wallet: `~/lez/wallet/configs/debug`, password `forum-protocol-dev`.
- **`ruint` must be pinned to 1.17.0 in each guest's OWN Cargo.lock**
  (`cd <guest dir> && cargo update -p ruint --precise 1.17.0`) — the risc0
  docker builder ships rustc 1.88, ruint 1.18 needs 1.90.
- Build guests in tmux at `-j4` (the keccak C++ kernels OOM'd the box and
  reset SSH at -j16). `libpython3.12-dev` installed for the wallet (pyo3).
- Deployed guest ImageIDs: membership_registry (slash-enabled)
  `6eca79ea50971688befcec8933459ce1776ae16e01906d7d6227c58fafd9e9c5`;
  post_proof (real Shamir) `3f2c559a601968be2033932ba798712b5e562f1bfe908cd33aba30369b78afc4`.
- Sync Mac→Hetzner: tar (exclude target/node_modules/.git/Cargo.lock) →
  scp → rsync into `~/forum-protocol`. Then re-pin ruint per guest.

## Repo map

```
programs/membership_registry/  core (Instruction, ForumState, verify_slash,
                                vendored shamir) + methods/guest (LEZ program)
programs/post_proof/            core (prove_post, shamir) + methods/guest
crates/moderation-cert/         N-of-M Ed25519 certs (share-bound)
crates/slash-evidence/          Lagrange reconstruction + build_slash_payload
crates/proof-host/              bench_post_proof, bench_any_elf
crates/lez-runner/              forum_register, forum_slash (live-chain runners)
crates/proof-daemon/            ⬜ P6.2 — currently a stub
sdk/                            @logos-forum/moderation-sdk (P6.1 API done)
app/                            ⬜ P7 reference Basecamp app
docs/                           SPEC, PLAN, STATUS(this), adr/, dev/, tasks/
```

## Conventions worth remembering

- **Commitment IS the Merkle leaf** (no extra leaf_hash). post_proof,
  membership_registry, and slash-evidence all agree — a bug here was
  caught by the slash-evidence round-trip test.
- **Two shamir copies**: `post_proof_core::shamir` (canonical) and
  `membership_registry_core::shamir` (vendored, because the guest docker
  context can't reach a cross-dir path dep). Cross-check test
  `slash-evidence::vendored_shamir_matches_original` guards drift — edit
  both together.
- Identity secrets must be canonical BN254 Fr (fits < ~254 bits) so
  `secret → Fr → bytes` round-trips for commitment matching.
