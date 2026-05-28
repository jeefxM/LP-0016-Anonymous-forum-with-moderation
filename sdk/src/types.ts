// Public types for @logos-forum/moderation-sdk.
//
// Every type here is forum-agnostic: the library deals in opaque
// `ContentId`s, never in forum-specific shapes like threads or comments.
// A consuming app decides what a ContentId hashes over.

/** 32-byte value, hex-encoded (no 0x prefix) at the API boundary. */
export type Hex32 = string;
/** 64-byte Ed25519 signature, hex-encoded. */
export type Hex64 = string;

/** Hash of whatever content the forum app wants moderated. App-defined. */
export type ContentId = Hex32;

/** Poseidon/SHA commitment to a member's identity secret. */
export type Commitment = Hex32;

/** An Ed25519 moderator public key, hex-encoded. */
export type ModeratorPubKey = Hex32;

/** Opaque handle to a forum instance. Carries the on-chain registry
 *  address and the instance's parameters. */
export interface ForumInstance {
	readonly forumId: string;
	/** On-chain registry PDA (base58 LEZ account id). */
	readonly registryAccount: string;
	/** Revocation threshold: K strikes → slash. */
	readonly kThreshold: number;
	/** Moderator quorum: N of M signatures issue one strike. */
	readonly nThreshold: number;
	/** The M configured moderator public keys. */
	readonly moderators: readonly ModeratorPubKey[];
	/** Stake (native units) required to register. */
	readonly stakeAmount: bigint;
	/** Current membership Merkle root. */
	readonly treeRoot: Hex32;
	/** Next free leaf index in the membership tree. */
	readonly nextLeafIndex: number;
}

/** A member's identity. The `secret` never leaves the caller's device —
 *  the SDK passes it only to the local proof daemon. */
export interface Identity {
	/** 32-byte identity secret, hex. Keep private. */
	readonly secret: Hex32;
	/** commitment = H("commit" || secret). Safe to publish. */
	readonly commitment: Commitment;
}

/** What a member attaches to a post so observers can verify membership
 *  without learning which member. Stored alongside the post in Waku. */
export interface PostEnvelope {
	readonly contentId: ContentId;
	readonly epoch: number;
	/** Public Merkle root the proof was made against. */
	readonly treeRoot: Hex32;
	/** Nullifier H(secret, epoch) — links a member's posts within an
	 *  epoch only. Choose epoch granularity to tune the anonymity set. */
	readonly nullifier: Hex32;
	/** Shamir share (x, y) of the member's secret, bound to this post. */
	readonly shareX: Hex32;
	readonly shareY: Hex32;
	/** The RISC0 receipt proving all of the above. Base64. */
	readonly receipt: string;
}

/** One moderator's signature on a strike against a post. */
export interface ModerationVote {
	readonly moderator: ModeratorPubKey;
	readonly contentId: ContentId;
	readonly strikeIndex: number;
	readonly shareX: Hex32;
	readonly shareY: Hex32;
	readonly signature: Hex64;
}

/** An aggregated N-of-M certificate against one post. Publicly auditable. */
export interface ModerationCertificate {
	readonly contentId: ContentId;
	readonly strikeIndex: number;
	readonly shareX: Hex32;
	readonly shareY: Hex32;
	readonly signatures: ReadonlyArray<{
		readonly moderator: ModeratorPubKey;
		readonly signature: Hex64;
	}>;
}

/** Everything needed to submit a slash, produced once K certs accumulate. */
export interface SlashEvidence {
	readonly commitment: Commitment;
	readonly reconstructedSecret: Hex32;
	readonly certificates: readonly ModerationCertificate[];
	readonly leafIndex: number;
	readonly merklePath: readonly Hex32[];
}

/** Typed error thrown by every SDK call. */
export class ForumError extends Error {
	constructor(
		readonly kind: ForumErrorKind,
		message: string,
	) {
		super(message);
		this.name = "ForumError";
	}
}

export type ForumErrorKind =
	| "daemon_unreachable" // local proof daemon not running
	| "proof_failed" // RISC0 proof generation failed (retryable)
	| "invalid_proof" // a post envelope failed verification
	| "revoked" // member is in the revocation set
	| "below_threshold" // not enough votes/certs
	| "chain_error" // LEZ submission failed
	| "transport_error" // Waku publish/subscribe failed
	| "not_found";
