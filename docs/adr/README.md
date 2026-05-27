# Architecture Decision Records

Each ADR captures one load-bearing decision: the context, the choice, the
alternatives we rejected, and the consequences we'll live with. We commit
ADRs at the moment of decision, not retroactively.

Filename: `ADR-NNN-short-kebab-title.md`.

## Index

| # | Title | Status |
|---|---|---|
| [ADR-001](./ADR-001-waku-only-storage.md) | Waku-only storage; defer Codex | Accepted |
| ADR-002 | RISC0 feasibility for post-proof (>10s pivot?) | Pending (P1.5) |
| ADR-003 | Threshold signature scheme: naive ≥N Ed25519 | Pending (P4) |
| ADR-004 | RISC0 prover location: localhost daemon | Pending (P6) |
| ADR-005 | Re-implement Semaphore+RLN natively in RISC0 | Pending (P1) |
| ADR-006 | Moderator key storage: password-encrypted software key | Pending (P7) |

## Template

```markdown
# ADR-NNN: Title

- **Status:** Proposed | Accepted | Superseded by ADR-XXX
- **Date:** YYYY-MM-DD
- **Phase:** P0 / P1 / ...

## Context

What's the situation that forces a decision? What constraints apply?

## Decision

What did we choose, in one paragraph.

## Alternatives considered

- Option A — why rejected
- Option B — why rejected

## Consequences

Good and bad. What this commits us to. Cost of reversing later.
```
