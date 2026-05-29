# Basecamp — reference forum app (LP-0016)

A demo-quality Next.js app that consumes **only** `@logos-forum/moderation-sdk`
to show the full anonymous-forum flow: create a forum, join with a ZK identity,
post anonymously (membership proven in < 10s with Groth16), moderate with a
2-of-3 threshold, and revoke a member after 3 strikes.

It imports nothing from the Rust crates directly — every chain/proof/Waku call
goes through the SDK, which talks to the local proof daemon (ADR-004) and a
Waku node (ADR-009).

## Architecture

```
browser (this app)
  ├─ @logos-forum/moderation-sdk
  │    ├─ HTTP → proof daemon  (proving, chain submit, pure crypto)
  │    └─ js-waku → nwaku       (posts, certificates, registration sync)
```

The proof daemon and nwaku run on a host with the prover + LEZ wallet (the
Hetzner box for this bounty). The browser reaches them over an SSH tunnel.

## Run it

1. **Bring up the backend** (on the box that has the daemon + nwaku + chain):
   - LEZ sequencer + bedrock node (see `docs/dev/local-sequencer.md`)
   - nwaku (see `docs/adr/ADR-009-waku-transport.md` for the run command)
   - proof daemon (`crates/proof-daemon`; see `docs/deployments.md`)

2. **Tunnel** the daemon + nwaku websocket to your laptop:
   ```sh
   ssh -N -L 8787:127.0.0.1:8787 -L 8000:127.0.0.1:8000 <host>
   ```

3. **Configure + start the app** (from the repo root):
   ```sh
   pnpm install
   NEXT_PUBLIC_WAKU_PEER=/ip4/127.0.0.1/tcp/8000/ws/p2p/<nwaku-peer-id> \
     pnpm --filter app dev
   ```
   Get `<nwaku-peer-id>` from nwaku's `GET /debug/v1/info` (`listenAddresses`).

4. Open <http://localhost:3000>.

### Environment variables

| var | default | meaning |
|---|---|---|
| `NEXT_PUBLIC_DAEMON_URL` | `http://127.0.0.1:8787` | proof daemon base URL |
| `NEXT_PUBLIC_WAKU_PEER` | (required) | nwaku `/ws` multiaddr to dial |
| `NEXT_PUBLIC_WAKU_CLUSTER_ID` | `2` | Waku cluster id (self-hosted, non-TWN) |
| `NEXT_PUBLIC_WAKU_SHARDS` | `8` | shards in the cluster |

## Demo flow

1. **Create demo forum** — 2-of-3 moderated, 3-strike revocation, with three
   pre-seeded moderator identities (mirrors `sdk/tests/lifecycle.mjs`).
2. **Create identity & join** — generates a ZK identity and registers it.
3. **Prove & post** — generates a Groth16 membership proof (shown live, < 10s)
   and publishes the post. Posts in the same epoch share a nullifier.
4. **Strike** — moderators sign a 2-of-3 certificate against a post.
5. **Reconstruct & slash** — after 3 strikes, the member's secret is
   reconstructed from the certificates and a slash is submitted on-chain. The
   member is then **revoked**.

## Known demo limitations

- **Post bodies are stored locally.** The SDK transports the opaque
  `ContentId` (the post's membership proof), not the text. This app keeps a
  local `contentId → text` map, so other browsers see a content hash rather
  than the prose. A production forum would publish the body on its own topic.
- **Single forum key per browser.** `createForum` generates a fresh symmetric
  forum key; joining the same forum from another instance would need that key
  shared out of band (a P9 concern for the two-instance demo).
- **Permissive CORS / localhost daemon.** The daemon is a localhost sidecar
  with `*` CORS — appropriate for the demo, not for exposure.
