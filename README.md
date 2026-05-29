# forum-protocol

Anonymous forum protocol with threshold moderation and membership revocation.
A submission for [Network School LP-0016][bounty].

> **Status:** Protocol, SDK, and reference app built; the membership registry
> is deployed and exercised live on the LEZ testnet (two instances). See
> [`docs/STATUS.md`](docs/STATUS.md) for the authoritative state.

## What this is

A forum-agnostic SDK + reference Logos Basecamp app that together implement:

- **Anonymous posting**: members post without revealing identity. Posts are
  unlinkable to any observer below the revocation threshold.
- **N-of-M moderation**: moderators jointly issue certificates against
  rule-violating content. No single moderator has unilateral power.
- **K-strike revocation**: once a member accumulates K certificates, anyone
  can submit an on-chain slash transaction that revokes their membership and
  claims their stake.

The cryptographic spine is the Semaphore + RLN construction, re-implemented
natively in RISC0 Rust for the Logos Execution Zone.

## Repo layout

```
programs/   LEZ programs (Rust + RISC0 guests)
crates/     Host-side Rust helpers
sdk/        @logos-forum/moderation-sdk — the forum-agnostic library
app/        Reference Basecamp forum app
docs/       SPEC, PLAN, protocol spec, ADRs
scripts/    Deployment + demo scripts
```

Full architectural detail in [`docs/SPEC.md`](docs/SPEC.md).
Phased build plan in [`docs/PLAN.md`](docs/PLAN.md).

## Live on LEZ testnet

Sequencer `https://testnet.lez.logos.co`. Membership registry (SPEL build,
ADR-012) program ID:

```
4766fcc24cac757ab4c504b3844c354468f4d7fbb7b630957573513c6eb9a30d
```

Two forum instances run live under this program with **different K and N-of-M
parameters** (each is a seed-derived `ForumState` PDA; `ForumConfig` carries the
parameters):

| | K | N-of-M | state PDA |
|---|---|---|---|
| Instance A | 3 | 2-of-3 | `A5tj58u7kXKYSNM1Yq2NvXULWkRmQ3SRMC5DaZuzCfKG` |
| Instance B | 2 | 3-of-4 | `29HtgrSfYa4AYy6GtysvdxtfNq3THZ2LudouXMRbPQre` |

Both ran `initialize → fund escrow → register-with-stake` live. Escrow PDAs, tx
hashes, and the CU costs are in [`docs/deployments.md`](docs/deployments.md) and
[`docs/cu-costs.md`](docs/cu-costs.md).

## Development

```bash
pnpm install
cargo check --workspace
just --list           # all available targets
```

More commands land as phases complete.

## License

MIT. See [LICENSE](./LICENSE).

[bounty]: https://ns.com/earn/lp-0016-anonymous-forum-with-threshold-moderation-and-membership-revocation
