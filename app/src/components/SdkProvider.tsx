"use client";

import {
  aggregateCertificate,
  createForumInstance,
  createIdentity,
  createPostProof,
  generateSymmetricKey,
  type ForumInstance,
  type Identity,
  isRevoked,
  loadForumInstance,
  MerkleTree,
  type ModerationVote,
  type PostEnvelope,
  publishCertificate,
  publishPost,
  register,
  signModerationVote,
  submitSlash,
  subscribePosts,
  subscribeRegistrations,
  tryReconstructSlashEvidence,
  verifyPostProof,
  WakuTransport,
} from "@logos-forum/moderation-sdk";
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import {
  contentIdFor,
  DAEMON_URL,
  DEFAULT_EPOCH,
  K_THRESHOLD,
  MODERATOR_SECRETS,
  N_THRESHOLD,
  STAKE_AMOUNT,
  WAKU_CLUSTER_ID,
  WAKU_PEER,
  WAKU_SHARDS,
} from "@/lib/forum";

export type Status = "disconnected" | "connecting" | "ready" | "error";

export interface FeedPost {
  envelope: PostEnvelope;
  text?: string;
  verified: boolean | null; // null = still checking
  reason?: string; // verify failure reason (e.g. "member has been revoked")
  struck: boolean;
}

interface SdkCtx {
  status: Status;
  error: string | null;
  forumId: string | null;
  forum: ForumInstance | null;
  identity: Identity | null;
  leafIndex: number | null;
  posts: FeedPost[];
  revoked: Set<string>;
  busy: string | null; // human label of the in-flight action
  lastProofMs: number | null;
  createForum: () => Promise<void>;
  joinIdentity: () => Promise<void>;
  composePost: (text: string, epoch: number) => Promise<void>;
  strike: (envelope: PostEnvelope) => Promise<void>;
  slashMember: (nullifier: string) => Promise<void>;
  strikesByNullifier: Record<string, number>;
}

const Ctx = createContext<SdkCtx | null>(null);
export const useSdk = (): SdkCtx => {
  const c = useContext(Ctx);
  if (!c) throw new Error("useSdk must be used within <SdkProvider>");
  return c;
};

export function SdkProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("disconnected");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [forumId, setForumId] = useState<string | null>(null);
  const [forum, setForum] = useState<ForumInstance | null>(null);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [leafIndex, setLeafIndex] = useState<number | null>(null);
  const [posts, setPosts] = useState<FeedPost[]>([]);
  const [revoked, setRevoked] = useState<Set<string>>(new Set());
  const [lastProofMs, setLastProofMs] = useState<number | null>(null);
  const [strikesByNullifier, setStrikes] = useState<Record<string, number>>({});

  // Stable handles reused across SDK calls.
  const treeRef = useRef<MerkleTree | null>(null);
  const transportRef = useRef<WakuTransport | null>(null);
  const textByContentId = useRef<Map<string, string>>(new Map());
  const seen = useRef<Set<string>>(new Set()); // dedupe feed by contentId+nullifier
  // forum readable inside async callbacks created before it's set in state.
  const forumRef = useRef<ForumInstance | null>(null);

  const config = useCallback(
    () => ({ daemonUrl: DAEMON_URL, tree: treeRef.current ?? undefined, transport: transportRef.current ?? undefined }),
    [],
  );

  const ingestPost = useCallback(
    (envelope: PostEnvelope) => {
      const key = `${envelope.nullifier}:${envelope.contentId}`;
      if (seen.current.has(key)) return;
      seen.current.add(key);
      const text = textByContentId.current.get(envelope.contentId);
      setPosts((prev) => [{ envelope, text, verified: null, struck: false }, ...prev]);
      // Verify membership asynchronously and update the badge.
      verifyPostProof(forumRef.current as ForumInstance, envelope, config())
        .then((r) =>
          setPosts((prev) =>
            prev.map((p) =>
              p.envelope.nullifier === envelope.nullifier && p.envelope.contentId === envelope.contentId
                ? { ...p, verified: r.valid, reason: r.reason }
                : p,
            ),
          ),
        )
        .catch(() => {
          /* leave as null */
        });
    },
    [config],
  );

  const createForum = useCallback(async () => {
    try {
      setError(null);
      setStatus("connecting");
      setBusy("Creating forum + connecting Waku");
      if (!WAKU_PEER) throw new Error("NEXT_PUBLIC_WAKU_PEER is not set");

      const id = `basecamp-${Date.now()}`;
      const tree = new MerkleTree();
      treeRef.current = tree;

      const transport = await WakuTransport.connect({
        forumId: id,
        peers: [WAKU_PEER],
        forumKey: generateSymmetricKey(),
        clusterId: WAKU_CLUSTER_ID,
        numShardsInCluster: WAKU_SHARDS,
      });
      transportRef.current = transport;

      // Derive the 3 pre-seeded moderator pubkeys (signModerationVote echoes it;
      // only contentId/shareX/shareY are read, the rest is a placeholder).
      const Z = "00".repeat(32);
      const dummy: PostEnvelope = { contentId: Z, epoch: 0, treeRoot: Z, nullifier: Z, shareX: Z, shareY: Z, receipt: "" };
      const moderators: string[] = [];
      for (const moderatorSecret of MODERATOR_SECRETS) {
        const v = await signModerationVote(
          { forum: null as never, moderatorSecret, envelope: dummy, strikeIndex: 0 },
          config(),
        );
        moderators.push(v.moderator);
      }

      const created = await createForumInstance(
        { forumId: id, moderators, nThreshold: N_THRESHOLD, kThreshold: K_THRESHOLD, stakeAmount: STAKE_AMOUNT },
        config(),
      );
      forumRef.current = created;
      setForum(created);
      setForumId(id);

      await subscribePosts(created, (env) => ingestPost(env), config());
      await subscribeRegistrations(created, config());

      setStatus("ready");
      setBusy(null);
    } catch (e) {
      setError(String(e));
      setStatus("error");
      setBusy(null);
    }
  }, [config, ingestPost]);

  const joinIdentity = useCallback(async () => {
    if (!forumRef.current) return;
    try {
      setBusy("Creating identity + registering");
      const id = await createIdentity(config());
      setIdentity(id);
      const reg = await register(forumRef.current, id, config());
      setLeafIndex(reg.leafIndex);
      // Refresh forum state (root advanced).
      forumRef.current = { ...forumRef.current, nextLeafIndex: reg.leafIndex + 1, treeRoot: treeRef.current!.root() };
      setForum(forumRef.current);
      setBusy(null);
    } catch (e) {
      setError(String(e));
      setBusy(null);
    }
  }, [config]);

  const composePost = useCallback(
    async (text: string, epoch: number) => {
      if (!forumRef.current || !identity) return;
      try {
        setBusy("Generating membership proof (Groth16)");
        const contentId = await contentIdFor(`${text}:${epoch}:${Date.now()}`);
        textByContentId.current.set(contentId, text);
        const t0 = performance.now();
        const envelope = await createPostProof(
          { forum: forumRef.current, identity, contentId, epoch: epoch || DEFAULT_EPOCH },
          config(),
        );
        setLastProofMs(Math.round(performance.now() - t0));
        await publishPost(forumRef.current, envelope, config());
        ingestPost(envelope);
        setBusy(null);
      } catch (e) {
        setError(String(e));
        setBusy(null);
      }
    },
    [config, identity, ingestPost],
  );

  const strike = useCallback(
    async (envelope: PostEnvelope) => {
      if (!forumRef.current) return;
      try {
        setBusy("Moderators signing strike (2-of-3)");
        const strikeIndex = strikesByNullifier[envelope.nullifier] ?? 0;
        const votes: ModerationVote[] = [];
        for (let m = 0; m < N_THRESHOLD; m++) {
          votes.push(
            await signModerationVote(
              { forum: forumRef.current, moderatorSecret: MODERATOR_SECRETS[m], envelope, strikeIndex },
              config(),
            ),
          );
        }
        const cert = await aggregateCertificate(forumRef.current, votes, config());
        await publishCertificate(forumRef.current, cert, config());
        setStrikes((s) => ({ ...s, [envelope.nullifier]: (s[envelope.nullifier] ?? 0) + 1 }));
        setPosts((prev) =>
          prev.map((p) =>
            p.envelope.contentId === envelope.contentId && p.envelope.nullifier === envelope.nullifier
              ? { ...p, struck: true }
              : p,
          ),
        );
        setBusy(null);
      } catch (e) {
        setError(String(e));
        setBusy(null);
      }
    },
    [config, strikesByNullifier],
  );

  const slashMember = useCallback(
    async (nullifier: string) => {
      if (!forumRef.current) return;
      try {
        setBusy("Reconstructing secret + submitting slash");
        const evidence = await tryReconstructSlashEvidence(forumRef.current, nullifier, config());
        if (!evidence) throw new Error("not enough strikes gathered to reconstruct");
        await submitSlash(forumRef.current, evidence, config());
        const after = await loadForumInstance(forumRef.current.forumId, config());
        forumRef.current = after;
        setForum(after);
        const isRev = await isRevoked(after, evidence.commitment, config());
        if (isRev) setRevoked((r) => new Set(r).add(evidence.commitment));
        setBusy(null);
      } catch (e) {
        setError(String(e));
        setBusy(null);
      }
    },
    [config],
  );

  const value = useMemo<SdkCtx>(
    () => ({
      status,
      error,
      forumId,
      forum,
      identity,
      leafIndex,
      posts,
      revoked,
      busy,
      lastProofMs,
      createForum,
      joinIdentity,
      composePost,
      strike,
      slashMember,
      strikesByNullifier,
    }),
    [
      status,
      error,
      forumId,
      forum,
      identity,
      leafIndex,
      posts,
      revoked,
      busy,
      lastProofMs,
      createForum,
      joinIdentity,
      composePost,
      strike,
      slashMember,
      strikesByNullifier,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
