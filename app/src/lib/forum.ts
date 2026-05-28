// Demo constants + small helpers shared across the reference app.
// The forum is a 2-of-3 moderated, 3-strike-to-revoke instance, mirroring
// sdk/tests/lifecycle.mjs.

export const K_THRESHOLD = 3; // strikes needed to slash (Shamir degree+1)
export const N_THRESHOLD = 2; // moderator signatures needed per cert
export const DEFAULT_EPOCH = 1;
export const STAKE_AMOUNT = 1000n;

// Pre-seeded moderator secrets (demo only). Each is a fixed 32-byte hex value,
// exactly as in lifecycle.mjs. The app derives pubkeys from these via the
// daemon (signModerationVote echoes the pubkey).
export const MODERATOR_SECRETS = ["a1", "b2", "c3"].map((b) => b.repeat(32));

export const DAEMON_URL = process.env.NEXT_PUBLIC_DAEMON_URL ?? "http://127.0.0.1:8787";
export const WAKU_PEER = process.env.NEXT_PUBLIC_WAKU_PEER ?? "";
// nwaku self-hosted cluster (non-TWN, no RLN) — see ADR-009.
export const WAKU_CLUSTER_ID = Number(process.env.NEXT_PUBLIC_WAKU_CLUSTER_ID ?? "2");
export const WAKU_SHARDS = Number(process.env.NEXT_PUBLIC_WAKU_SHARDS ?? "8");

/** Opaque ContentId for a post body: SHA-256(text) as 32-byte hex. */
export async function contentIdFor(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const short = (hex: string, n = 8): string =>
  hex.length <= n * 2 ? hex : `${hex.slice(0, n)}…${hex.slice(-4)}`;
