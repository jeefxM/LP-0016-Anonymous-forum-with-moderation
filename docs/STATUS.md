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
| **P6 SDK + Waku** | 🟡 in progress |
| ↳ P6.1 SDK public API surface | ✅ done (`sdk/src/{types,index}.ts`, typechecks) |
| ↳ P6.2 proof-daemon (Rust HTTP) | ⬜ **NEXT** |
| ↳ P6.3 SDK client → daemon | ⬜ |
| ↳ P6.4 Waku transport (js-waku) | ⬜ delegatable (pure TS, contract = types.ts) |
| ↳ P6.5 SDK smoke test | ⬜ |
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

## Immediate next action (P6.2)

Build `crates/proof-daemon` — an axum localhost HTTP server wrapping the
proven crates. Architecture per ADR-004: SDK is a thin client; the daemon
does all ZK proving + LEZ submission (secret never leaves localhost);
js-waku does transport. Endpoints map 1:1 to the SDK API in
`sdk/src/index.ts`:

- pure crypto (Mac-buildable): sign_vote, aggregate_cert, verify_cert
  (moderation-cert); reconstruct_slash (slash-evidence)
- proving (Hetzner only — needs RISC0 prover + guest ELF): prove_post,
  verify_post (post_proof_core + proof-host)
- chain (Hetzner only — needs WalletCore): register, submit_slash,
  load_instance (reuse lez-runner patterns)

The daemon, like lez-runner, path-deps the LEZ sibling checkout and is
**excluded from the Mac workspace** (root `Cargo.toml` exclude list).

## Loose ends / backlog (these were tracked as in-session tasks)

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
