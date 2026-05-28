// @logos-forum/moderation-sdk
//
// A forum-agnostic SDK for anonymous posting, N-of-M threshold moderation,
// and K-strike membership revocation on the Logos stack (LEZ + Waku).
//
// Design (see docs/SPEC.md, ADR-004):
//   - All zero-knowledge proving and LEZ chain submission happen in a local
//     Rust proof daemon. The SDK is a typed client to it. The member's
//     identity secret is sent only to localhost, never over the network.
//   - Off-chain content + certificate transport rides Waku (see ./transport).
//   - The library knows nothing about threads, comments, or posts — only
//     opaque `ContentId`s. Any forum shape can be built on top.

export * from "./types";

import type {
	Commitment,
	ContentId,
	ForumInstance,
	Hex32,
	Identity,
	ModerationCertificate,
	ModerationVote,
	ModeratorPubKey,
	PostEnvelope,
	SlashEvidence,
} from "./types";

export interface SdkConfig {
	/** Base URL of the local proof daemon. Default http://127.0.0.1:8787. */
	daemonUrl?: string;
	/** Waku node multiaddr(s) for transport. */
	wakuPeers?: string[];
}

// ─── 1. Forum instance lifecycle ─────────────────────────────────────

/** Create a new forum instance on-chain with the given parameters. The
 *  caller becomes able to register members against it. */
export declare function createForumInstance(
	params: {
		forumId: string;
		moderators: ModeratorPubKey[];
		nThreshold: number;
		kThreshold: number;
		stakeAmount: bigint;
	},
	config?: SdkConfig,
): Promise<ForumInstance>;

/** Load an existing instance's current state (root, leaf index, config). */
export declare function loadForumInstance(
	forumId: string,
	config?: SdkConfig,
): Promise<ForumInstance>;

// ─── 2. Membership ───────────────────────────────────────────────────

/** Generate a fresh member identity. The secret stays with the caller. */
export declare function createIdentity(config?: SdkConfig): Promise<Identity>;

/** Register `identity` in `forum`, staking `forum.stakeAmount`. Submits the
 *  on-chain Register transaction via the daemon. */
export declare function register(
	forum: ForumInstance,
	identity: Identity,
	config?: SdkConfig,
): Promise<{ leafIndex: number; txHash: string }>;

/** True if `commitment` is in the instance's on-chain revocation set. */
export declare function isRevoked(
	forum: ForumInstance,
	commitment: Commitment,
	config?: SdkConfig,
): Promise<boolean>;

// ─── 3. Posting (member side) ────────────────────────────────────────

/** Produce a `PostEnvelope` for `contentId`: a ZK proof of non-revoked
 *  membership plus a Shamir share bound to this post. Proving runs in the
 *  local daemon and may take several seconds. On failure the caller can
 *  retry without consuming anything (nullifier is deterministic). */
export declare function createPostProof(
	params: {
		forum: ForumInstance;
		identity: Identity;
		contentId: ContentId;
		epoch: number;
	},
	config?: SdkConfig,
): Promise<PostEnvelope>;

/** Verify a `PostEnvelope`. A forum app calls this before rendering a post:
 *  checks the receipt, that the proof targets the current `treeRoot`, and
 *  that the member is not revoked. */
export declare function verifyPostProof(
	forum: ForumInstance,
	envelope: PostEnvelope,
	config?: SdkConfig,
): Promise<{ valid: boolean; reason?: string }>;

// ─── 4. Moderation (moderator side) ──────────────────────────────────

/** A moderator signs a strike against the post identified by `contentId`,
 *  binding the post's Shamir share into the signature. */
export declare function signModerationVote(
	params: {
		forum: ForumInstance;
		moderatorSecret: Hex32;
		envelope: PostEnvelope;
		strikeIndex: number;
	},
	config?: SdkConfig,
): Promise<ModerationVote>;

/** Aggregate ≥ N independent votes into one certificate. Fails below N. */
export declare function aggregateCertificate(
	forum: ForumInstance,
	votes: ModerationVote[],
	config?: SdkConfig,
): Promise<ModerationCertificate>;

/** Publish a certificate to Waku so it is publicly auditable. */
export declare function publishCertificate(
	forum: ForumInstance,
	cert: ModerationCertificate,
	config?: SdkConfig,
): Promise<void>;

// ─── 5. Slashing (any party) ─────────────────────────────────────────

/** Fetch all published certificates targeting a given member commitment. */
export declare function listCertificatesForMember(
	forum: ForumInstance,
	commitment: Commitment,
	config?: SdkConfig,
): Promise<ModerationCertificate[]>;

/** Try to assemble slash evidence from accumulated certificates. Returns
 *  null if fewer than K certs are available. The reconstruction (Shamir
 *  Lagrange) runs in the daemon. */
export declare function tryReconstructSlashEvidence(
	forum: ForumInstance,
	commitment: Commitment,
	config?: SdkConfig,
): Promise<SlashEvidence | null>;

/** Submit a slash transaction. Anyone may call this once evidence exists;
 *  the on-chain verifier re-checks everything. Revokes the member and
 *  claims their stake. */
export declare function submitSlash(
	forum: ForumInstance,
	evidence: SlashEvidence,
	config?: SdkConfig,
): Promise<{ txHash: string }>;

export const SDK_VERSION = "0.0.1";
