# ADR-004: Prover location is a localhost daemon, and the daemon is stateless about the tree

- **Status:** Accepted
- **Date:** 2026-05-28
- **Phase:** P6.2

## Context

The SDK (`@logos-forum/moderation-sdk`) is TypeScript and runs in a forum
app. Two operations need heavy Rust that does not belong in a browser or a
JS process:

1. **ZK proving** — `createPostProof` runs the RISC0 post-proof guest. The
   prover is native Rust (risc0-zkvm) and takes tens of seconds (ADR-002).
2. **LEZ chain submission** — `register`, `createForumInstance`,
   `submitSlash` build and send `nssa` transactions via `WalletCore`, which
   path-deps the LEZ workspace and is not a JS-friendly dependency.

Both also touch the member's **identity secret**, which must never leave the
member's machine.

Separately, building the daemon surfaced a second decision. `register` needs
`path_before` (the empty-leaf sibling path at `leaf_index`), and
`createPostProof` needs the member's `merkle_siblings` + `path_bits`, both
against the *current* membership tree. The on-chain `ForumState` stores only
`tree_root` + `next_leaf_index`, not the leaf set. There is no incremental-
tree/frontier helper in core, and the LEZ RPC (`sequencer_service_rpc`)
exposes only `get_account` / `get_block(_range)` / `get_transaction` — no
cheap "list all instructions for this PDA." So the leaf set is reconstructable
only by walking every block, and each member runs their own daemon (so one
daemon does not naturally observe another's registrations).

## Decision

**The prover and chain submitter live in a single localhost HTTP daemon
(`crates/proof-daemon`, axum). The SDK is a thin typed client to it. The
identity secret is sent only to `127.0.0.1`, never over the network.**

**The daemon is stateless about the membership tree. Merkle paths and
siblings are *inputs* to the daemon's HTTP endpoints, supplied by the
caller.** The daemon never reconstructs, caches, or persists the tree; it
re-queries the PDA per call for live `tree_root` / `next_leaf_index` /
`revocation_set`, and treats `path_before` / `merkle_siblings` / `path_bits`
as request fields it trusts the client to compute correctly (the on-chain
guest re-verifies every path against the root regardless, so a wrong path
just fails the transaction — it is not a trust hole).

The membership tree itself is public data and is owned by the **TypeScript
transport/SDK layer**: a small incremental Merkle frontier (16 left
siblings, O(depth) update per new commitment) fed by the commitments seen on
Waku. That belongs to P6.4 (Waku transport) / P6.3 (SDK client), not the
daemon. The app-facing SDK signatures (`register(forum, identity)`,
`createPostProof({forum, identity, contentId, epoch})`) stay clean — the SDK
fills in the path from its local frontier before calling the daemon.

## Alternatives considered

- **Daemon owns an in-memory tree.** Wrong by construction: each member's
  daemon is independent, so it would not see other members' registrations
  unless fed by Waku — and once it's Waku-fed, the natural home is the TS
  transport layer, not the Rust daemon.
- **Add `commitments: Vec<Commitment>` to `ForumState`.** Reopens P2,
  changes the membership_registry ImageID, forces a redeploy, and bloats
  on-chain state for data that is already public off-chain.
- **Daemon replays chain history** via `get_block_range`. No per-account tx
  index exists, so this means walking all blocks — unknown cost, a research
  detour, and still needs the daemon to be long-lived/synced. Parked as a
  possible v2 source of truth if LEZ later exposes a per-account tx feed.
- **Bonsai / remote prover.** Rejected for v1 (ADR-002): adds an external
  dependency the bounty's "Logos stack for all off-chain activity" wording
  is ambiguous about. Kept as a perf fallback only.

## Consequences

- The daemon is "the proven Rust crates over HTTP" and nothing more — easy
  to reason about, test, and keep aligned with `lez-runner`.
- The P6.2 smoke test works today with `empty_path()` (leaf 0, single
  member), exactly like `forum_register.rs`, with no tree manager existing
  anywhere yet.
- P6.3/P6.4 carry a real, non-trivial deliverable: a correct TS incremental
  frontier. If that is buggy, paths are wrong and transactions fail — but
  safely (the chain rejects them; no bad state is committed).
- For dev, the daemon loads the wallet once at boot from
  `NSSA_WALLET_HOME_DIR` (password `forum-protocol-dev`). An `/unlock`
  endpoint is deferred to P6.5/P7 (see ADR-006).
- `createPostProof` blocks its HTTP request for the full proof duration
  (~tens of seconds). The SDK must set a generous fetch timeout. A job-id +
  polling model is a v2 option, noted in the daemon code.
