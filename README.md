# forum-protocol

Anonymous forum protocol with threshold moderation and membership revocation.
A submission for [Network School LP-0016][bounty].

> **Status:** Phase 0 (foundations). Not usable yet.

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
