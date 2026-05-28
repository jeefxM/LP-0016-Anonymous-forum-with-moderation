# ADR-003: Naive ≥N independent Ed25519 signatures for moderation certificates

- **Status:** Accepted
- **Date:** 2026-05-28
- **Phase:** P4

## Context

LP-0016 requires that N of M designated moderators must agree before a
moderation certificate can be issued against forum content. Several
threshold-signature schemes fit:

1. **Naive ≥N independent signatures** — every moderator signs the same
   message individually with their own Ed25519 key. Cert = list of
   `(pubkey, signature)` pairs. Verifier checks each one.
2. **FROST** — threshold Schnorr/Ed25519 signatures. M moderators run a
   distributed key generation, produce a single short signature that any
   verifier can check with a single public key. Crypto-elegant, requires
   careful DKG implementation.
3. **BLS threshold** — similar to FROST but with BLS curve. Aggregation
   is trivial; setup is heavier.

## Decision

**Naive ≥N independent Ed25519 signatures for v1.**

The wire format (already defined in
`programs/membership_registry/core/src/lib.rs`):

```rust
pub struct ModerationCertificateWire {
    pub content_id: Hash,
    pub strike_index: u8,
    pub signatures: Vec<(ModeratorPubKey, ModeratorSig)>,
}
```

Implementation lives in `crates/moderation-cert/`.

## Alternatives considered

### FROST

Pros: single short signature on-chain, simpler verifier, less storage.

Cons: distributed key generation (DKG) is the failure mode — getting it
wrong leaks shares or produces unforgeable-but-incorrect signatures.
Reference Rust implementations exist (`frost-ed25519`, `frost-dalek`)
but every team that's deployed FROST has had to handle:

- Moderator key-rotation flow (re-run DKG)
- Add-a-moderator flow (DKG again)
- Lost-share recovery
- Per-session nonce coordination

Each of these would add a week or more to v1. We're not paying that for
a $1,200 bounty.

### BLS threshold

Same DKG concerns as FROST. Also requires a BLS-aware verifier inside
the LEZ guest. Adds a heavy cryptographic dependency for marginal gain.

## Consequences

### Good

- Implementation is ~280 LOC of pure Rust with comprehensive negative-
  path tests (8 passing).
- Verification in the slash guest is "loop over signatures, check each."
  Trivial to reason about and audit.
- Moderator key rotation is trivial: drop one pubkey from the
  configured set, add another. No DKG ceremony.
- The wire format is a clean `Vec<(pubkey, sig)>` — debuggable, easy
  to inspect on chain explorers.

### Bad / committed-to

- **Cert size grows linearly with N.** Each signature is 64 bytes + 32
  bytes for the pubkey = 96 bytes. A 9-of-15 cert costs ~864 bytes on
  the wire, vs ~64 bytes for FROST. For LEZ instruction-data limits
  this is fine; we'd need to revisit if N grows past ~30.
- **On-chain verification cost grows linearly with N.** Each Ed25519
  verify is ~5 000 RISC0 cycles (with the accelerator). A 9-of-15
  cert is ~45 000 cycles inside the slash guest's verification loop.
  Within a single segment's budget; not a concern at these N values.
- **No public aggregate key.** Frontends can't show "the moderator
  team's signature" — they have to enumerate. Not a UX issue for v1.

## v2 upgrade path

If a forum operator wants larger moderator sets (M > 20), or if the
bounty submission needs to demonstrate cleaner crypto, the migration to
FROST is straightforward:

1. Add a `signature_scheme: Scheme` field to `ForumConfig` (currently
   implicit).
2. Pull in `frost-ed25519`, wire DKG into the SDK.
3. Update the slash guest to dispatch on `scheme` — naive vs FROST.

Forum instances created under v1 keep the naive scheme. New instances
pick.
