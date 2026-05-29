# forum-protocol

Anonymous forum protocol with threshold moderation and membership revocation.
A submission for [Network School LP-0016][bounty].

> **Status:** Protocol, SDK, and reference app built; the membership registry
> is deployed and exercised live on the LEZ testnet with two instances
> (see [`docs/deployments.md`](docs/deployments.md)).

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

## End-to-end usage

The full lifecycle — create a forum instance → register → post anonymously →
moderate (N-of-M) → accumulate strikes → slash → revoke — runs two ways.

### Via the reference Basecamp app (no CLI, no manual tx)

The app imports only `@logos-forum/moderation-sdk`. Backend bring-up (LEZ
sequencer + nwaku + proof daemon), the SSH tunnel, and the required env vars are
documented in [`app/README.md`](app/README.md). Once the backend is up:

```sh
pnpm install
NEXT_PUBLIC_WAKU_PEER=/ip4/127.0.0.1/tcp/8000/ws/p2p/<peer-id> pnpm --filter app dev
# open http://localhost:3000
```

Then click through the numbered panels:

1. **Forum** — *Create demo forum* deploys a forum instance (2-of-3 moderation,
   3-strike revocation) with three seeded moderator identities.
2. **Identity** — *Create identity & join* generates a ZK identity and registers
   the commitment on-chain, locking the stake.
3. **Post anonymously** — write a post; a Groth16 membership proof is generated
   in <10 s and published. Posts in the same epoch share a nullifier; the author
   is otherwise unlinkable.
4. **Feed & moderation** — a 2-of-3 moderator quorum *Strikes* a post (an N-of-M
   certificate). After 3 strikes, *Slash* reconstructs the member's secret from
   the certificates, submits the on-chain slash, and the member is revoked —
   their subsequent posts are rejected.

### One-command demo (`just demo`)

With the backend up, from the repo root:

```sh
NWAKU_PEER=/ip4/127.0.0.1/tcp/8000/ws/p2p/<peerId> just demo
```

[`scripts/demo.mjs`](scripts/demo.mjs) runs the full
register → post → 3× strike → slash → revoke flow through SDK imports against
the live stack, and exits non-zero on any failed invariant. Chain transactions
(register, slash) are executed and proven by the standalone sequencer with
`RISC0_DEV_MODE=0` — real STARK proofs, not dev-mode receipts; the membership
proof is Groth16. The same flow backs the SDK integration reference
[`sdk/tests/lifecycle.mjs`](sdk/tests/lifecycle.mjs).

### On the public testnet

The membership registry is live (program ID above) with the two instances. To
create more instances or reproduce the live flow, see the command sequence and
tx hashes in [`docs/deployments.md`](docs/deployments.md); bringing the local
stack back up is documented there too.

> **Note:** real-proof (`RISC0_DEV_MODE=0`) execution costs for register and
> slash are in [`docs/cu-costs.md`](docs/cu-costs.md).

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
