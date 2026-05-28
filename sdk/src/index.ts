// @logos-forum/moderation-sdk
//
// A forum-agnostic SDK for anonymous posting, N-of-M threshold moderation,
// and K-strike membership revocation on the Logos stack (LEZ + Waku).
//
// Design (see docs/SPEC.md, ADR-004):
//   - All zero-knowledge proving and LEZ chain submission happen in a local
//     Rust proof daemon. The SDK is a typed client to it. The member's
//     identity secret is sent only to localhost, never over the network.
//   - The SDK owns the membership Merkle tree (`config.tree`): it computes
//     the paths the daemon needs for register/createPostProof. The tree is
//     fed by commitments seen on Waku (P6.4); for now the SDK appends on its
//     own registrations.
//   - Off-chain content + certificate transport rides Waku (P6.4).
//   - The library knows nothing about threads, comments, or posts — only
//     opaque `ContentId`s. Any forum shape can be built on top.

export * from "./types.js";
export * from "./tree.js";
export * from "./transport.js";
export { DEFAULT_DAEMON_URL } from "./client.js";

import { daemonPost } from "./client.js";
import { ForumError } from "./types.js";
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
} from "./types.js";
import type { MerkleTree } from "./tree.js";
import type { WakuTransport } from "./transport.js";

export interface SdkConfig {
	/** Base URL of the local proof daemon. Default http://127.0.0.1:8787. */
	daemonUrl?: string;
	/** Waku node multiaddr(s) for transport (P6.4). */
	wakuPeers?: string[];
	/**
	 * The SDK's view of the membership tree. Required for `register` and
	 * `createPostProof`, which derive Merkle paths from it (ADR-004). The
	 * caller owns it across calls; `subscribeRegistrations` keeps it in sync
	 * from Waku.
	 */
	tree?: MerkleTree;
	/**
	 * A connected Waku transport (ADR-009). Required for the post/cert/slash
	 * functions that publish to or read from Waku. Create once with
	 * `WakuTransport.connect(...)` and reuse across calls.
	 */
	transport?: WakuTransport;
}

// Daemon `ForumInstance` wire shape (stakeAmount is a decimal string).
interface ForumInstanceWire {
	forumId: string;
	registryAccount: string;
	kThreshold: number;
	nThreshold: number;
	moderators: string[];
	stakeAmount: string;
	treeRoot: string;
	nextLeafIndex: number;
}

function toForumInstance(w: ForumInstanceWire): ForumInstance {
	return {
		forumId: w.forumId,
		registryAccount: w.registryAccount,
		kThreshold: w.kThreshold,
		nThreshold: w.nThreshold,
		moderators: w.moderators,
		stakeAmount: BigInt(w.stakeAmount),
		treeRoot: w.treeRoot,
		nextLeafIndex: w.nextLeafIndex,
	};
}

function requireTree(config?: SdkConfig): MerkleTree {
	if (!config?.tree) {
		throw new ForumError(
			"bad_request",
			"config.tree (MerkleTree) is required for this operation",
		);
	}
	return config.tree;
}

function requireTransport(config?: SdkConfig): WakuTransport {
	if (!config?.transport) {
		throw new ForumError(
			"transport_error",
			"config.transport (a connected WakuTransport) is required for this operation",
		);
	}
	return config.transport;
}

// ─── 1. Forum instance lifecycle ─────────────────────────────────────

/** Create a new forum instance on-chain with the given parameters. */
export async function createForumInstance(
	params: {
		forumId: string;
		moderators: ModeratorPubKey[];
		nThreshold: number;
		kThreshold: number;
		stakeAmount: bigint;
	},
	config?: SdkConfig,
): Promise<ForumInstance> {
	const wire = await daemonPost<ForumInstanceWire>(config?.daemonUrl, "/v1/forum/create", {
		forumId: params.forumId,
		moderators: params.moderators,
		nThreshold: params.nThreshold,
		kThreshold: params.kThreshold,
		stakeAmount: params.stakeAmount.toString(),
	});
	return toForumInstance(wire);
}

/** Load an existing instance's current state (root, leaf index, config). */
export async function loadForumInstance(
	forumId: string,
	config?: SdkConfig,
): Promise<ForumInstance> {
	const wire = await daemonPost<ForumInstanceWire>(config?.daemonUrl, "/v1/forum/load", {
		forumId,
	});
	return toForumInstance(wire);
}

// ─── 2. Membership ───────────────────────────────────────────────────

/** Generate a fresh member identity. The secret stays with the caller. */
export async function createIdentity(config?: SdkConfig): Promise<Identity> {
	return daemonPost<Identity>(config?.daemonUrl, "/v1/identity/create", {});
}

/** Register `identity` in `forum`. Derives `path_before` from the local
 *  tree, submits the on-chain Register, then appends the commitment. */
export async function register(
	forum: ForumInstance,
	identity: Identity,
	config?: SdkConfig,
): Promise<{ leafIndex: number; txHash: string }> {
	const tree = requireTree(config);
	if (tree.size !== forum.nextLeafIndex) {
		throw new ForumError(
			"bad_request",
			`local tree out of sync: tree has ${tree.size} leaves but forum.nextLeafIndex is ${forum.nextLeafIndex}`,
		);
	}
	if (tree.root() !== forum.treeRoot) {
		throw new ForumError("bad_request", "local tree root does not match forum.treeRoot");
	}

	const leafIndex = forum.nextLeafIndex;
	const pathBefore = tree.siblings(leafIndex);
	const resp = await daemonPost<{ leafIndex: number; txHash: string }>(
		config?.daemonUrl,
		"/v1/member/register",
		{ forumId: forum.forumId, commitment: identity.commitment, pathBefore, leafIndex },
	);
	tree.append(identity.commitment);
	// Announce the new leaf so other members' trees can sync (ADR-009).
	// Best-effort: a forum with no transport configured just skips it.
	if (config?.transport) {
		await config.transport.publishRegistration({ leafIndex, commitment: identity.commitment });
	}
	return resp;
}

/** True if `commitment` is in the instance's on-chain revocation set. */
export async function isRevoked(
	forum: ForumInstance,
	commitment: Commitment,
	config?: SdkConfig,
): Promise<boolean> {
	const resp = await daemonPost<{ revoked: boolean }>(
		config?.daemonUrl,
		"/v1/member/is-revoked",
		{ forumId: forum.forumId, commitment },
	);
	return resp.revoked;
}

// ─── 3. Posting (member side) ────────────────────────────────────────

/** Produce a `PostEnvelope` for `contentId`. Derives the member's
 *  membership path from the local tree, then proves in the daemon (may take
 *  tens of seconds). Retryable — the nullifier is deterministic. */
export async function createPostProof(
	params: {
		forum: ForumInstance;
		identity: Identity;
		contentId: ContentId;
		epoch: number;
	},
	config?: SdkConfig,
): Promise<PostEnvelope> {
	const tree = requireTree(config);
	const index = tree.indexOf(params.identity.commitment);
	if (index < 0) {
		throw new ForumError(
			"not_found",
			"member commitment is not in the local tree (register or sync via Waku first)",
		);
	}
	if (tree.root() !== params.forum.treeRoot) {
		throw new ForumError(
			"bad_request",
			"local tree root does not match forum.treeRoot (sync the tree before proving)",
		);
	}

	return daemonPost<PostEnvelope>(config?.daemonUrl, "/v1/post/prove", {
		secret: params.identity.secret,
		treeRoot: params.forum.treeRoot,
		merkleSiblings: tree.siblings(index),
		pathBits: tree.pathBits(index),
		contentId: params.contentId,
		epoch: params.epoch,
		kThreshold: params.forum.kThreshold,
	});
}

/** Verify a `PostEnvelope` against the current chain state. */
export async function verifyPostProof(
	forum: ForumInstance,
	envelope: PostEnvelope,
	config?: SdkConfig,
): Promise<{ valid: boolean; reason?: string }> {
	return daemonPost<{ valid: boolean; reason?: string }>(
		config?.daemonUrl,
		"/v1/post/verify",
		{ forumId: forum.forumId, envelope },
	);
}

// ─── 3b. Transport: posts + tree sync (Waku) ─────────────────────────

/** Publish a post envelope to the forum's Waku posts topic (ADR-009). */
export async function publishPost(
	_forum: ForumInstance,
	envelope: PostEnvelope,
	config?: SdkConfig,
): Promise<void> {
	await requireTransport(config).publishPost(envelope);
}

/** Subscribe to new post envelopes on the forum's Waku posts topic. Invokes
 *  `onPost` for each. A forum app renders its feed from these. */
export async function subscribePosts(
	_forum: ForumInstance,
	onPost: (envelope: PostEnvelope) => void,
	config?: SdkConfig,
): Promise<void> {
	await requireTransport(config).subscribePosts(onPost);
}

/** Keep `config.tree` in sync with the forum's membership by replaying and
 *  subscribing to the registrations topic (ADR-009). Registrations are
 *  applied in leafIndex order. After the initial replay the local tree
 *  should match `forum.treeRoot`; if it doesn't, the Waku Store window has
 *  expired and the tree can't be fully rebuilt from Waku alone. */
export async function subscribeRegistrations(
	forum: ForumInstance,
	config?: SdkConfig,
	onUpdate?: () => void,
): Promise<void> {
	const tree = requireTree(config);
	const transport = requireTransport(config);
	await transport.syncRegistrations(tree, onUpdate);
}

// ─── 4. Moderation (moderator side) ──────────────────────────────────

/** A moderator signs a strike against the post identified by `contentId`,
 *  binding the post's Shamir share into the signature. */
export async function signModerationVote(
	params: {
		forum: ForumInstance;
		moderatorSecret: Hex32;
		envelope: PostEnvelope;
		strikeIndex: number;
	},
	config?: SdkConfig,
): Promise<ModerationVote> {
	return daemonPost<ModerationVote>(config?.daemonUrl, "/v1/moderation/sign", {
		moderatorSecret: params.moderatorSecret,
		contentId: params.envelope.contentId,
		strikeIndex: params.strikeIndex,
		shareX: params.envelope.shareX,
		shareY: params.envelope.shareY,
	});
}

/** Aggregate ≥ N independent votes into one certificate. Fails below N. */
export async function aggregateCertificate(
	forum: ForumInstance,
	votes: ModerationVote[],
	config?: SdkConfig,
): Promise<ModerationCertificate> {
	return daemonPost<ModerationCertificate>(config?.daemonUrl, "/v1/moderation/aggregate", {
		nThreshold: forum.nThreshold,
		votes,
	});
}

/** Publish a certificate to the forum's Waku certs topic so any member can
 *  audit it and assemble slash evidence (ADR-009). */
export async function publishCertificate(
	_forum: ForumInstance,
	cert: ModerationCertificate,
	config?: SdkConfig,
): Promise<void> {
	await requireTransport(config).publishCertificate(cert);
}

// ─── 5. Slashing (any party) ─────────────────────────────────────────

/** Fetch the certificates targeting a member identified by `nullifier`
 *  (ADR-009). A slasher computes the nullifier from a flagged post envelope
 *  they're investigating; the transport joins the posts topic
 *  (contentId → nullifier) against the certs topic. */
export async function listCertificatesByNullifier(
	_forum: ForumInstance,
	nullifier: Hex32,
	config?: SdkConfig,
): Promise<ModerationCertificate[]> {
	return requireTransport(config).listCertificatesByNullifier(nullifier);
}

/** Try to assemble slash evidence for the member behind `nullifier`. Gathers
 *  certs from Waku, reconstructs the secret + commitment in the daemon
 *  (`/v1/slash/recover`), then fills the Merkle path from the local tree.
 *  Returns null if fewer than K certs are available. */
export async function tryReconstructSlashEvidence(
	forum: ForumInstance,
	nullifier: Hex32,
	config?: SdkConfig,
): Promise<SlashEvidence | null> {
	const tree = requireTree(config);
	const certificates = await listCertificatesByNullifier(forum, nullifier, config);
	if (certificates.length < forum.kThreshold) return null;

	const recovered = await daemonPost<{
		reconstructedSecret: string;
		commitment: string;
	} | null>(config?.daemonUrl, "/v1/slash/recover", {
		forumId: forum.forumId,
		certificates,
	});
	if (!recovered) return null;

	const leafIndex = tree.indexOf(recovered.commitment);
	if (leafIndex < 0) {
		throw new ForumError(
			"not_found",
			"recovered commitment is not in the local tree (sync the tree before slashing)",
		);
	}

	return {
		commitment: recovered.commitment,
		reconstructedSecret: recovered.reconstructedSecret,
		certificates,
		leafIndex,
		merklePath: tree.siblings(leafIndex),
	};
}

/** Submit a slash transaction. Anyone may call this once evidence exists;
 *  the on-chain verifier re-checks everything. */
export async function submitSlash(
	forum: ForumInstance,
	evidence: SlashEvidence,
	config?: SdkConfig,
): Promise<{ txHash: string }> {
	return daemonPost<{ txHash: string }>(config?.daemonUrl, "/v1/slash/submit", {
		forumId: forum.forumId,
		reconstructedSecret: evidence.reconstructedSecret,
		certificates: evidence.certificates,
		leafIndex: evidence.leafIndex,
		merklePath: evidence.merklePath,
	});
}

export const SDK_VERSION = "0.0.1";
