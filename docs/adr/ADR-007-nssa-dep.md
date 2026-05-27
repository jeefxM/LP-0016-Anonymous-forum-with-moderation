# ADR-007: Depend on nssa_core via pinned git commit

- **Status:** Accepted
- **Date:** 2026-05-28
- **Phase:** P2.1

## Context

LEZ programs must call `read_nssa_inputs` / construct `AccountPostState` /
emit `ProgramOutput`. These types live in the `nssa_core` crate inside the
public LEZ workspace:

  https://github.com/logos-blockchain/logos-execution-zone

We need a way to depend on `nssa_core` from our guest crate
(`programs/membership_registry/methods/guest`) and our host runner
(`crates/lez-runner`).

Three options:

1. **Path dependency** to the local `../lez` checkout.
2. **Git dependency** pinned to a specific commit.
3. **Vendor** the needed types into our own crate.

## Decision

**Git dependency, pinned to commit `8c8f5b57`** (LEZ `main` as of
2026-05-28). The pin updates manually in PRs that bump LEZ versions; we
don't track `main`.

```toml
[dependencies]
nssa_core = { git = "https://github.com/logos-blockchain/logos-execution-zone", rev = "8c8f5b57" }
```

## Alternatives considered

- **Path dep `../../../lez/nssa/core`** — works locally on the dev Mac
  where the LEZ clone sits next to us, but breaks on Hetzner CI and
  contributor checkouts because the path drifts. The docker build for
  guests does `COPY . .` of the manifest directory; pulling a sibling
  workspace into the build context is awkward. Rejected.
- **Vendor the types** — reproduces ~37 KB of `program.rs` and dependent
  modules in our tree. Stays usable when LEZ is offline but creates a
  maintenance burden every time LEZ tweaks `AccountPostState` or
  `ProgramOutput`. Rejected for v1.

## Consequences

- `cargo risczero build` inside its docker container fetches the LEZ
  repo via git. First build is slower (network), cached after.
- Bumping the LEZ version is a one-line ADR addendum + lockfile update.
- We are still free to vendor if Logos closes the repo or LEZ
  development moves to a private fork.
