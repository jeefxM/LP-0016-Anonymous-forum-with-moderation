# Protocol specification

Anonymous, moderated forums on the Logos stack (LP-0016). This document is the
required protocol spec: the unlinkability argument, anonymity-set analysis,
the retroactive-deanonymization-on-slash property, the moderator trust model,
the revocation mechanism, and the threat model.

It describes *what the protocol guarantees and assumes*. Implementation
decisions and their rationale live in the ADRs (`docs/adr/`), referenced
throughout. Where a property depends on a specific construction, the exact
preimages are in **ADR-010**.

## 1. System model

A **forum instance** is an independent deployment with its own membership
registry (a LEZ program account), moderator set, and parameters `K` (strikes
to revoke) and `N`-of-`M` (signatures per strike). Instances share no state.

Three layers, by design (ADR-001, ADR-004):

- **On-chain (LEZ):** the membership registry program. It holds the
  membership Merkle root, the revocation set, and per-forum config. Only two
  operations touch the chain: **registration** (one-time, per member) and
  **slash** (once per revoked member). Posting and moderation never touch the
  chain. Registration also locks a per-forum **stake** that the slasher claims
  on revocation — the economic skin-in-the-game behind the `K`-strike rule
  (implementation status in §8).
- **Local prover (daemon):** generates and verifies the zero-knowledge
  membership proofs and submits chain transactions. The member's identity
  secret never leaves localhost (ADR-004).
- **Off-chain transport (Waku):** post envelopes, moderation certificates,
  and registration announcements (ADR-009). Publicly readable; certificates
  are auditable by anyone.


### Roles

- **Member:** holds a secret, registers a commitment, posts anonymously.
- **Moderator:** one of the `M` keys in a forum's config. `N` must co-sign to
  strike a post.
- **Slasher:** anyone (a moderator or any third party) who gathers `K`
  certificates against one member and submits the slash.

## 2. Cryptographic primitives

All hashes are SHA-256 with ASCII domain tags; the field is the BN254 scalar
field `r`. Exact byte layouts are in ADR-010 §"Circuit specification".

| Object | Definition |
|---|---|
| identity secret | random canonical `Fr` (`< r`), 32 bytes, held by the member |
| commitment | `SHA256("commit" ‖ secret)` — the Merkle leaf, safe to publish |
| Merkle tree | depth 16 (≤ 65 536 members), node `= SHA256("node" ‖ l ‖ r)` |
| nullifier | `SHA256("null" ‖ secret ‖ epoch_LE)` |
| share x | `from_le_bytes_mod_order(SHA256("shamir/x" ‖ secret ‖ contentId))` |
| polynomial | `coeff[0] = secret`; `coeff[i] = from_le(SHA256("shamir/coeff" ‖ secret ‖ i_LE))`, degree `K-1` |
| share y | `Σ coeff[i]·x^i` evaluated at the post's share x (Horner, over `Fr`) |
| membership proof | Groth16 circuit (ADR-010): proves `commitment ∈ tree(root)` and emits `(nullifier, shareX, shareY)` for public `(root, epoch, contentId)` |
| moderation cert | `≥ N` Ed25519 signatures over `SHA256("forum-protocol/v1/modcert" ‖ contentId ‖ strikeIndex ‖ shareX ‖ shareY)` |

The membership proof generates in **< 10 s** (measured ~4.7 s end-to-end on
the build host; witness generation is single-threaded and laptop-equivalent,
see ADR-010 for the laptop-equivalence argument). It reveals nothing about
*which* member produced it — only that some non-revoked registered member did,
and the post-bound nullifier and Shamir share.

### Why a Shamir share per post

Each post carries one point `(shareX, shareY)` on the member's degree-`(K-1)`
polynomial. The polynomial is fixed by `(secret, K)`; `shareX` is unique per
`contentId`. Collecting `K` points for **distinct content** reconstructs
`coeff[0] = secret` by Lagrange interpolation. This is the bridge from "K
strikes" to "deanonymize + revoke": no share reveals the secret, but `K` of
them do. The reconstruction is re-verified on-chain (ADR-008), so a slasher
cannot submit a forged secret.

## 3. Unlinkability and the anonymity set

### Anonymity set

A valid post proves membership against the current tree root. The anonymity
set is therefore **every non-revoked registered commitment in the tree** —
up to `2^16 = 65 536` per instance. An observer learns only that the author
is one of them. Newly registered members enlarge the set; slashed members
leave it (their commitment is in the revocation set and their posts are
rejected — §5).

### What is and isn't linkable

- **Different epochs ⇒ unlinkable.** The nullifier is `H(secret, epoch)`, and
  each proof is an independent Groth16 proof. Two posts by the same member in
  different epochs share no observable value. There is no persistent handle.
- **Same epoch ⇒ linkable by nullifier (intentional).** Posts in one epoch
  share a nullifier. This is the knob that makes moderation possible: it lets
  moderators (and anyone) see that several posts came from one member *within
  that epoch*, which is what gathering `K` strikes against one member requires.
  Members tune their exposure by choosing epoch granularity — fewer posts per
  epoch means a smaller linkable cluster.
- **`contentId` and `epoch` are public inputs**; `secret`, the Merkle path,
  and which leaf is the author are private. The bind check in the verifier
  (ADR-010) ties the proof's public signals to the envelope, so a proof can't
  be replayed against a different `(root, epoch, contentId)`.

### Precise note on shares vs. epochs

The polynomial and `shareX` depend on `(secret, contentId)` only — **not** on
`epoch`. So `K` shares for distinct content lie on the same polynomial
regardless of which epoch each post was in. In practice certificates are
gathered per member by joining the posts topic (`contentId → nullifier`)
against the certs topic (ADR-009), which clusters by nullifier (i.e., by
epoch). The cryptographic reconstruction, however, only needs `K`
distinct-content shares of one secret.

## 4. Retroactive deanonymization on slash

This property is required by the bounty and is **intended**:

> Once a member is slashed, the reconstructed secret is published on-chain
> (`ForumState.revoked_secrets`). Anyone can then recompute that member's
> nullifier for *any* epoch (`H(secret, epoch)`) and link **all** of their
> past and future posts. No other member's anonymity is affected — only the
> slashed member's secret is revealed; every other secret stays private.

In other words, anonymity is *conditional*: it holds exactly until a member
accumulates `K` strikes. Below the threshold, a member is unlinkable across
epochs and unidentifiable within the set. At the threshold, they are fully and
retroactively deanonymized. This is the accountability that makes anonymous
posting compatible with moderation. It is enforced, not just observable: the
verifier rejects any post whose nullifier matches a revoked secret (§5).

## 5. Revocation mechanism

1. **Accumulate.** `N`-of-`M` moderators co-sign a certificate against a post
   (binding the post's `(shareX, shareY)`). Certificates are published to Waku
   and are publicly auditable. Fewer than `N` signatures cannot form a
   certificate — enforced client-side before any chain interaction.
2. **Reconstruct.** When `K` certificates for distinct content of one member
   are gathered, a slasher reconstructs `secret` by Lagrange interpolation.
3. **Slash (on-chain).** The slasher submits one `Slash` transaction. The
   registry's `verify_slash` (ADR-008) independently re-checks, inside the
   zkVM: each certificate has `≥ N` valid signatures from configured
   moderators; each `shareX = H(secret, contentId)` and each `shareY` lies on
   the polynomial implied by the submitted secret (so a forged secret fails);
   the resulting `commitment` is in the tree and not already revoked.
4. **Revoke.** On success the registry adds the commitment to
   `revocation_set` and publishes the reconstructed secret in
   `revoked_secrets`.
5. **Reject future posts.** A post envelope is anonymous (nullifier, no
   commitment), so a revoked member cannot be matched by commitment. Instead,
   the verifier recomputes `H("null" ‖ revoked_secret ‖ epoch)` for the post's
   proven epoch and rejects any match (`post_proof_core::is_revoked_post`).
   Because the secret is published, this holds for every epoch — a revoked
   member cannot escape by rotating epochs.

The common path (post, moderate) costs no gas; only registration and slash are
on-chain (ADR-001).

## 6. Moderator trust model

- **No unilateral power.** A single moderator cannot strike: `N` distinct
  configured keys must co-sign each certificate. Revocation needs `K` such
  certificates.
- **Public audit trail.** Every certificate is published to Waku and verifies
  against the forum's moderator set. Selective or unjustified enforcement is
  visible; a dissatisfied community can fork the instance.
- **Bounded power.** Moderators hold only the shares carried by posts they
  moderate. Below `K` shares they learn nothing about a member's secret — they
  cannot deanonymize a member who has not crossed the threshold.
- **What `N` colluding moderators *can* do.** They can issue strikes against
  any post they choose. If a member has produced `K` posts whose shares the
  moderators can gather (distinct content), `N` colluding moderators can
  revoke and deanonymize that member. They cannot fabricate strikes against a
  member who has not posted enough distinct content to yield `K` shares — the
  shares come from the member's own posts (possibly across epochs, since a
  share depends on `(secret, contentId)` not `epoch`; §3), and `verify_slash`
  binds each share to the real secret. This is the core trust assumption: **a forum's
  moderators (at the `N`-of-`M` threshold) are trusted to apply the `K`-strike
  rule honestly; the protocol guarantees they cannot do so unilaterally,
  silently, or against a member who has not generated the evidence.**

## 7. Threat model

**Assumptions.** SHA-256 and Ed25519 are secure; BN254 / Groth16 soundness
holds (demo-grade trusted setup — single-contributor, documented in ADR-010,
not a production ceremony); the LEZ sequencer correctly executes and verifies
zkVM receipts (`RISC0_DEV_MODE=0` for real proofs); the member's device and
local daemon are honest (the secret lives there); Waku delivers messages
within its Store retention window (ADR-001).

| Threat | Mitigation |
|---|---|
| Non-member forges a post | Membership proof requires a commitment in the tree; the Groth16 circuit is sound. |
| Replay a valid proof against different content/epoch | Verifier bind-check ties public signals to the envelope `(root, epoch, contentId)` byte-for-byte (ADR-010). |
| Post against a stale root (e.g., after others changed it) | Verifier requires the proof's root to equal the current on-chain root. |
| Revoked member keeps posting | Verifier rejects any post whose nullifier matches a published revoked secret, in any epoch (§5). |
| Single moderator censors | `N`-of-`M` threshold; one signature is insufficient. |
| Moderator key compromise | An attacker must compromise `N` distinct moderator keys to issue one strike, and sustain that across `K` certificates to revoke; fewer than `N` is inert. Choose `N`/`M` for the desired compromise tolerance. |
| Slasher submits a forged secret to revoke an innocent member | `verify_slash` binds every certificate share to the secret (`shareX = H(secret, contentId)`, `shareY = poly(shareX)`); a forged secret fails. |
| Slasher pads with duplicate certificates | `verify_slash` rejects duplicate `contentId`s; `K` *distinct* shares are required. |
| Double-slash / re-slash | `verify_slash` rejects a commitment already in the revocation set. |
| Linking a member's posts across epochs (pre-slash) | Different epochs yield independent nullifiers and proofs; no shared observable. |
| Deanonymize a below-threshold member | Requires `K` shares of one secret; fewer reveal nothing (Shamir threshold). |
| Network observer correlates by metadata | Out of scope at the protocol layer; posts/certs are symmetric-encrypted on Waku (ADR-009), but timing/IP correlation is a transport concern. |

**Out of scope (LP-0016):** discovery/search/feeds; reputation or rate limits;
cross-forum identity linking; end-to-end content encryption (the transport
uses a per-forum symmetric key, ADR-009, but rich E2E is not required);
anything beyond what the reference app needs.

## 8. Known limitations

- **Staking.** `stake_amount` is a per-forum config value. Locking value on
  register and claiming it on slash require nssa cross-program value movement
  (a program may only debit accounts it owns), which is in progress; see
  STATUS. The revocation and moderation guarantees above do not depend on it.
- **Waku Store window.** Posts and certificates are only retrievable within
  the node's Store retention window (ADR-001). The membership tree can be
  rebuilt from the registration topic only while those messages persist;
  beyond that, clients fall back to a trusted snapshot of the on-chain root.
- **Trusted setup.** The Groth16 setup is single-contributor (demo-grade). A
  production deployment needs a multi-party ceremony (ADR-010).
- **Anonymity-set size in practice.** The theoretical maximum is `2^16`, but
  the *effective* set is the number of non-revoked members who have actually
  registered in an instance. Small instances offer weaker anonymity.
