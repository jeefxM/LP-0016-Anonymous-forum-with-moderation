# ADR-001: Waku-only storage; defer Codex

- **Status:** Accepted
- **Date:** 2026-05-28
- **Phase:** P0

## Context

LP-0016 requires "the Logos stack for all off-chain activity." The Logos
stack offers two storage primitives:

- **Waku** — gossip-based messaging with Store, Filter, and LightPush
  protocols. Best-effort retention bounded by node Store windows (days–weeks).
- **Codex** — durable content-addressed storage with erasure coding. The
  right tool for "this content must survive for years."

The bounty's success criteria do not mention durability or archival. The
demo regenerates its own content on every run. Per `SPEC.md` we are scoping
strictly to bounty deliverables — no productization for Network School or
forumzero in v1.

## Decision

The reference forum app and SDK use **Waku Store + LightPush + Filter only**.
Codex integration is out of scope for v1.

The Basecamp demo app surfaces a small banner clarifying that content
retention follows the Waku Store window, so a reviewer sees the choice was
deliberate.

## Alternatives considered

- **Waku + Codex from day one.** Adds ~1.5 weeks for integration, schema, and
  retrieval flow. The bounty does not value this work, so it would directly
  trade against schedule risk on the load-bearing pieces (P1 spike, SDK, app).
- **Waku only with a "consider Codex later" TODO.** Same outcome as this ADR
  but undocumented. We prefer an explicit decision record over silent omission
  so a future contributor doesn't burn time wondering why we didn't use Codex.

## Consequences

- We accept that demo content vanishes after the Waku Store window. Acceptable
  for a bounty demo. Unacceptable for any productized variant — which is
  explicitly out of scope here.
- The SDK's content-fetching API is shaped around a Waku content topic + time
  range, not a content-addressed CID. Migrating to Codex later would add a
  second retrieval path, not replace the first.
- We do not need to learn Codex's API surface or run a Codex node in CI. CI
  runs Waku locally only.
