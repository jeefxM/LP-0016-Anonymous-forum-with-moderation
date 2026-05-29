# Demo video runbook (LP-0016)

A recording guide, not a deliverable. Narrate in your own words; the bullets
are talking points, the code blocks are exactly what to put on screen. Target
length 8 to 12 minutes. The bounty needs narration (not a silent screencast),
an architecture + decisions walkthrough, the full lifecycle, and terminal
output that confirms `RISC0_DEV_MODE=0` and shows proof generation.

## Before you hit record

On the build host (Hetzner), confirm the stack is up:

```sh
tmux ls                       # expect: bedrock, seq, daemon
ps aux | grep sequencer_service | grep -o 'RISC0_DEV_MODE=[01]'   # expect 0
curl -s http://127.0.0.1:8787/v1/health                            # {"status":"ok",...}
```

Local checklist:
- Big terminal font, dark theme, wide window. Two panes help (commands left,
  a `tail -f ~/seq.log` right).
- Have these tabs ready: the repo in an editor (README, docs/protocol.md,
  docs/deployments.md), a terminal on the host, and the testnet wallet env
  (`NSSA_WALLET_HOME_DIR=~/wallet-testnet`).
- Decide on cuts: the chain steps in `just demo` take a couple of minutes. You
  can speed-ramp the waits in editing, but never cut the proof-generation shot
  or the `RISC0_DEV_MODE=0` reveal.

## Segment 1 — What and why (45s, talking head or a title slide)

- This is LP-0016: an anonymous forum with threshold moderation and membership
  revocation.
- Two deliverables: a forum-agnostic moderation SDK, and a reference Basecamp
  app built on it without modification.
- The property that matters: members post anonymously and their posts are
  unlinkable, yet an N-of-M moderator quorum can act on content, and a member
  who collects K strikes is revoked on-chain and retroactively deanonymized.
- Nothing touches the chain on the common path. Only registration and the final
  slash are on-chain; posting and moderation are off-chain over Waku.

## Segment 2 — Architecture and key decisions (2 to 3 min, screen-share)

Show the repo layout and `docs/protocol.md`. Walk the three layers:

1. On-chain membership registry, a LEZ program (RISC0 guest). Handles
   registration with stake, the revocation list, and slash verification. Built
   with the SPEL framework so it ships an IDL.
2. Off-chain over Waku: anonymous post envelopes and moderation certificates.
   Publicly auditable, no gas.
3. The ZK layer: a Groth16 membership proof (proves "I'm a registered,
   non-revoked member" without revealing which one) and a per-post nullifier.

Call out the decisions with their reasons (point at the ADRs):
- Waku-only off-chain storage so the common path is gasless (ADR-001).
- Semaphore-style commitment + nullifier for unlinkability (ADR-010); same
  epoch shares a nullifier, different epochs do not.
- Shamir secret sharing binds a share into every post; K moderation certs
  reconstruct the member's secret, which is what enables retroactive
  deanonymization on slash (ADR-008).
- N-of-M as a naive Ed25519 multi-signature certificate, threshold enforced
  client-side before anything goes on-chain (ADR-003).
- Staking via a registry-owned escrow PDA funded through authenticated_transfer
  (ADR-011).
- Ported the on-chain program to SPEL for the IDL and the testnet deploy
  (ADR-012).

Mention the anonymity set is the full set of non-revoked members, and point at
the threat model section in `docs/protocol.md`.

## Segment 3 — Tests and proof realness (1 to 2 min, terminal)

Show the seven bounty-named tests pass:

```sh
cargo test --workspace --exclude proof-host
```

Point out the names in the output: `valid_registration`, `valid_post_proof`,
`moderation_cert_construction`, `moderation_cert_verification`,
`strike_accumulation`, `slash_submission`, `post_rejection_after_revocation`.

Then the mandatory `RISC0_DEV_MODE=0` proof shot. This binary prints the env
banner, generates a real STARK proof, and verifies it:

```sh
RISC0_DEV_MODE=0 ./target/release/bench_post_proof \
  programs/post_proof/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/post_proof.bin
```

Narrate as it runs: "RISC0_DEV_MODE is 0, so this is a real proof, not a
dev-mode receipt." Let the camera catch `prove() OK`, the cycle count, and
`verify() OK`. Also show the sequencer's env so the audience sees the chain
proves for real too:

```sh
ps aux | grep sequencer_service | grep -o 'RISC0_DEV_MODE=[01]'
```

Accuracy note for narration: the membership post-proof is Groth16 (sub-10s,
see `docs/cu-costs.md`); `RISC0_DEV_MODE` governs the RISC0 chain guest
(register/slash) and the bench above. Don't claim the membership proof is
RISC0. The point you're proving here is "no dev-mode shortcuts anywhere."

## Segment 4 — Full lifecycle, end to end (3 to 4 min, terminal — the centerpiece)

In one pane, tail the sequencer so the audience sees it execute each chain tx:

```sh
tail -f ~/seq.log
```

In the other pane, run the demo:

```sh
NWAKU_PEER=/ip4/127.0.0.1/tcp/8000/ws/p2p/<peerId> just demo
```

Narrate each line as it prints:
- create forum instance, register a member (stake locked; watch seq.log execute
  the register guest).
- post anonymously: a membership proof is generated, the post publishes. Three
  posts in one epoch share a nullifier but carry distinct Shamir shares, so
  they're unlinkable to observers yet reconstructable once K certs exist.
- moderators sign N-of-M certificates against the posts.
- the slasher gathers K certs by nullifier, reconstructs the secret, and submits
  one slash transaction. Read out the slash tx hash. The member is revoked.
- close the loop on post rejection: a revoked member's nullifier now matches the
  published revoked-secret, so their future posts are rejected (the
  `post_rejection_after_revocation` test is this property).

End on `FULL LIFECYCLE OK`.

## Segment 5 — Live on the testnet (1 to 2 min, terminal)

Show the two live instances, with different K and N-of-M, on one deployed
program. Open `docs/deployments.md` to the table, then read one instance live:

```sh
NSSA_WALLET_HOME_DIR=~/wallet-testnet \
  wallet account get -a Public/29HtgrSfYa4AYy6GtysvdxtfNq3THZ2LudouXMRbPQre -r
```

Point out: program ID `4766fcc2...`, Instance A is K=3 / 2-of-3, Instance B is
K=2 / 3-of-4, and `next_leaf_index` shows a member registered with stake. This
is the "two live instances with different parameters and verified program IDs"
criterion.

Optional, for the "non-technical user" angle: switch to the Basecamp app at
`http://localhost:3000` and click the four panels (Forum, Identity, Post,
Feed & moderation) to show the same lifecycle without a CLI.

## Segment 6 — Wrap (30s)

- Recap against the criteria: anonymous unlinkable posting, N-of-M moderation,
  K-strike slash with retroactive deanonymization, parameterizable instances,
  a forum-agnostic SDK, an app that uses it unmodified, an IDL via SPEL, two
  live testnet instances, and documented CU costs.
- Mention the repo is MIT, the demo is reproducible with `just demo`, and the
  protocol spec and threat model live in `docs/protocol.md`.

## If a step misbehaves on the day

- Daemon or nwaku down: `scripts/demo.mjs` fails fast and tells you where to
  look. Bring the stack back up per `docs/deployments.md` "Restarting the local
  chain", re-confirm `/v1/health`, retry.
- `just` not present on the host: run `node scripts/demo.mjs` directly with the
  same `NWAKU_PEER` / `DAEMON_URL` env.
- Get the nwaku peer id from `curl -s http://127.0.0.1:8645/debug/v1/info` and
  use the `/ws` multiaddr.
