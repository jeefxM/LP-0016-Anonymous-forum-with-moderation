# ADR-009: Waku transport — topics, symmetric-only encryption, nullifier-keyed certs

- **Status:** Accepted
- **Date:** 2026-05-28
- **Phase:** P6.4

## Context

P6.4 builds the SDK's off-chain transport on Waku (ADR-001: Waku Store +
LightPush + Filter, no Codex). It must carry three message kinds and feed
the SDK's membership `MerkleTree` (ADR-004). Designing it against the
*actual* P6.3 SDK surface surfaced two mismatches with the early SPEC table.

## Decision

### Content topics (per forum, format version 1)

```
/forum-protocol/1/<forumId>-reg/proto    registrations (tree-sync)
/forum-protocol/1/<forumId>-post/proto   post envelopes
/forum-protocol/1/<forumId>-cert/proto   moderation certificates
```

Messages are JSON (the same hex/base64 wire shapes the daemon uses), encoded
to bytes for the Waku payload.

### Encryption: symmetric-only; ECIES deferred

- **Registrations — plaintext.** They carry `{ leafIndex, commitment }`.
  Commitments are already public on-chain; encrypting them would force every
  tree-sync subscriber to hold the symmetric key just to learn what the chain
  already exposes.
- **Posts and certs — symmetric** (`@waku/message-encryption/symmetric`) with
  a per-forum content key supplied via `SdkConfig.forumKey`. This makes forum
  content members-only readable, which is what "publicly auditable" means in
  practice here — auditable *within the forum*, not to the open internet.
- **ECIES — not implemented.** The SPEC's "ECIES for share-reveal" assumed
  moderators exchange votes peer-to-peer over Waku. They don't in this
  architecture: `signModerationVote` runs in the local daemon and the caller
  passes the `Vote` straight into `aggregateCertificate`. No SDK function
  encrypts to a recipient public key, so adding an ECIES path would be code
  with no consumer. If vote-exchange ever moves onto Waku, revisit and add
  `@waku/message-encryption/ecies` then.

### Cert lookup is keyed by nullifier, not commitment

`listCertificatesForMember(commitment)` (P6.1) is anonymity-incompatible: a
certificate carries `(contentId, shareX, shareY, signatures)` and never the
member commitment — that is the anonymity guarantee. The only public link
between a member's posts is the **nullifier** `H(secret, epoch)`, and only
within one epoch. So:

- Renamed to **`listCertificatesByNullifier(forum, nullifier)`**. A slasher
  computes the nullifier from a flagged post envelope they are investigating,
  then fetches the certs sharing it.
- `tryReconstructSlashEvidence(forum, nullifier)` likewise takes a nullifier.

### Slash needs `recover` before the Merkle path

The daemon's `/v1/slash/reconstruct` needs `leafIndex` + `merklePath` as
inputs, but the slasher only learns the member's commitment *after*
reconstructing the secret from the shares. To break the cycle, the daemon
gains **`/v1/slash/recover`**: it reconstructs `(reconstructedSecret,
commitment)` from K certs (verifying each cert, no Merkle check). The SDK
then looks the commitment up in `config.tree` to get `leafIndex` +
`merklePath`, assembles the full `SlashEvidence`, and submits it (the
on-chain verifier re-checks everything per ADR-008).

### Tree-sync ordering and the Store window

- Registrations arrive over Waku out of order. The SDK applies them to
  `config.tree` strictly by `leafIndex`, buffering gaps until contiguous. On
  `subscribeRegistrations`, it first replays the forum's registration topic
  from Waku Store, then live-subscribes via Filter.
- After applying, the SDK asserts `tree.root() === forum.treeRoot` (the
  on-chain root) — the same sync-correctness check the P6.3 integration used.
- **Limitation:** Waku Store retention is days–weeks (ADR-001). A forum older
  than the Store window cannot have its tree fully rebuilt from Waku alone;
  registrations beyond the window are lost. Acceptable for a bounty demo; the
  Basecamp app surfaces the Store-window banner ADR-001 already requires.

### Node: local nwaku for tests only

The SDK connects a `createLightNode` to a statically-dialed nwaku multiaddr
(`SdkConfig.wakuPeers`). For dev/CI we bring up a local nwaku on demand; a
dedicated long-lived node for the P9 demo is decided in P9.

## New SDK surface (additive to P6.1)

`publishPost`, `subscribePosts`, `publishCertificate`,
`listCertificatesByNullifier`, and an internal `subscribeRegistrations` that
feeds `config.tree`. `listCertificatesForMember` is removed in favour of the
nullifier variant.

## Consequences

- A `transport/` module is the only place `@waku/*` is imported (SPEC's
  import boundary). The rest of the SDK stays Waku-agnostic.
- The forum content key is a shared secret distributed out of band; the SDK
  takes it via config and does not manage key distribution in v1.
- Deferring ECIES keeps P6.4 to one encryption path. The decision is
  reversible: adding ECIES later is additive, not a rewrite.
