# ADR-008: On-chain slash must bind certificates to shares

- **Status:** Accepted (design); implementation deferred
- **Date:** 2026-05-28
- **Phase:** P5 (discovered while wiring slash-evidence)

## Context

The slash flow has an off-chain aggregator (`crates/slash-evidence`) and
an on-chain verifier (the `Slash` branch of the membership_registry LEZ
guest). While wiring the off-chain side I found a gap in what the
on-chain side can verify.

### The flow

1. K moderators each sign a certificate against a member's posts. A
   cert authenticates `(content_id, strike_index)`.
2. Each flagged post carries a Shamir share `(share_x, share_y)` of the
   member's identity secret, derived in the post_proof guest.
3. The slasher collects K certs + the K post envelopes (which carry the
   shares), reconstructs the secret via Lagrange, and submits a `Slash`
   transaction.

### The gap

The off-chain `build_slash_payload` checks `cert.content_id ==
envelope.content_id` and reconstructs honestly. But the **on-chain**
guest only receives `(reconstructed_secret, certs, merkle_path)` — it
does **not** see the shares or envelopes. So on-chain, nothing binds the
submitted secret to the certs.

A malicious slasher who holds:

- K legitimately-signed certs against member **A** (content_ids A1..AK), and
- knowledge of member **B**'s secret

…could submit `Slash { secret: B_secret, certs: A_certs }`. The guest
would check "certs are valid signatures" ✓ and "commitment_of(B_secret)
is in the tree" ✓ and wrongly revoke **B**.

(In practice the attacker can only *learn* B's secret by reconstructing
it from K of B's shares — so they'd need K flagged B-posts too. But we
should not rely on that; the on-chain check must be sound on its own.)

## Decision

**Bind the share into the certificate, and have the on-chain guest verify
that every cert's share lies on the polynomial implied by the submitted
secret.**

### Certificate format change

Moderators sign over `(content_id, strike_index, share_x, share_y)`
instead of just `(content_id, strike_index)`. The share is now
authenticated as belonging to that content_id.

### On-chain verification (the elegant part)

Given the submitted `reconstructed_secret`, the guest:

1. Derives the full polynomial coefficients deterministically:
   `coeffs = polynomial_coefficients(secret, K)`.
2. For each cert, checks `poly_eval(coeffs, cert.share_x) == cert.share_y`.
3. Verifies each cert has ≥ N valid moderator signatures.
4. Verifies `commitment_of(secret)` is in the tree (Merkle proof).
5. Adds the commitment to the revocation set.

Step 2 is the binding. If the slasher submits B's secret with A's certs,
then `poly_eval(B_coeffs, A_share_x) != A_share_y` (A's shares lie on A's
polynomial, not B's), so the check fails. **The guest never runs
Lagrange** — it only evaluates the polynomial K times, which is much
cheaper (no field inversions).

This keeps reconstruction off-chain (slasher's job) while making the
on-chain check fully sound.

## Consequences

### Good

- On-chain slash is trustless: no honest-slasher assumption.
- Polynomial evaluation is cheap (~K × degree field mults); far less than
  on-chain Lagrange (which needs K inversions).
- The off-chain `slash-evidence` still does Lagrange to *find* the secret;
  the on-chain side only *checks* it. Clean division of labor.

### Implementation cost (deferred)

This changes three things already built in P4/P5:

1. **`moderation-cert`** — `sign_vote` and `message_to_sign` must include
   `(share_x, share_y)`. `Vote` and `ModerationCertificateWire` carry the
   share.
2. **`slash-evidence`** — `build_slash_payload` includes shares in the
   on-chain payload; certs already carry them after (1).
3. **membership_registry guest `Slash` branch** — implement steps 1-5
   above. Needs `ark-bn254` (poly_eval), `ed25519-dalek` (sig verify),
   `sha2` (merkle + commitment) inside the guest. All three are
   no_std-capable and RISC0-buildable.

Tracked as a P5.6 task. Tonight's integration block focuses on getting
**Register** working end-to-end on a live sequencer; the real Slash
branch lands in the session that does this redesign.

### Why this wasn't caught earlier

The P4/P5 unit tests exercise the *off-chain* aggregator, which is honest
by construction. The gap only exists at the on-chain trust boundary,
which we hadn't reached until starting the live-sequencer integration.
This is exactly the kind of issue the integration block is meant to
surface — better now than after the SDK is built on top.
