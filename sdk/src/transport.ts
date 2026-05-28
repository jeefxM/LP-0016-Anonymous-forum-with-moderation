// Waku transport (ADR-009). The ONLY module that imports `@waku/*` — the
// rest of the SDK stays Waku-agnostic.
//
// Three per-forum content topics: registrations (plaintext, tree-sync),
// posts and certs (symmetric-encrypted with a per-forum key). The pure
// join/ordering logic is factored out (selectCertsForNullifier,
// RegistrationSync) so it is unit-testable without a live node.

import {
	createLightNode,
	type IDecodedMessage,
	type IDecoder,
	type IEncoder,
	type LightNode,
	Protocols,
} from "@waku/sdk";
import {
	createDecoder as createSymDecoder,
	createEncoder as createSymEncoder,
	generateSymmetricKey,
} from "@waku/message-encryption/symmetric";

import type { MerkleTree } from "./tree.js";
import { ForumError } from "./types.js";
import type { Commitment, ModerationCertificate, PostEnvelope } from "./types.js";

export { generateSymmetricKey };

/** What a registration message carries — the minimum to extend the tree. */
export interface RegistrationMsg {
	leafIndex: number;
	commitment: Commitment;
}

export interface TransportOptions {
	forumId: string;
	/** nwaku multiaddrs to dial. */
	peers: string[];
	/** Per-forum symmetric key for posts + certs (32 bytes). */
	forumKey: Uint8Array;
	/** Static-sharding cluster/shard the nwaku node serves. */
	clusterId?: number;
	shard?: number;
}

function topics(forumId: string) {
	const base = `/forum-protocol/1/${forumId}`;
	return {
		reg: `${base}-reg/proto`,
		post: `${base}-post/proto`,
		cert: `${base}-cert/proto`,
	};
}

const encodeJson = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
const decodeJson = <T>(p: Uint8Array): T => JSON.parse(new TextDecoder().decode(p)) as T;

// ── Pure logic (unit-testable, no Waku) ──────────────────────────────

/**
 * Given all posts + all certs in a forum, return one certificate per
 * distinct contentId authored under `nullifier`. Certs never name the
 * member (anonymity); the post envelopes provide the contentId → nullifier
 * link (ADR-009). Dedupes to one cert per contentId — K distinct strikes is
 * what slash reconstruction needs.
 */
export function selectCertsForNullifier(
	posts: PostEnvelope[],
	certs: ModerationCertificate[],
	nullifier: string,
): ModerationCertificate[] {
	const contentIds = new Set(posts.filter((p) => p.nullifier === nullifier).map((p) => p.contentId));
	const seen = new Set<string>();
	const out: ModerationCertificate[] = [];
	for (const c of certs) {
		if (contentIds.has(c.contentId) && !seen.has(c.contentId)) {
			seen.add(c.contentId);
			out.push(c);
		}
	}
	return out;
}

/**
 * Applies registration messages to a MerkleTree in leafIndex order,
 * buffering out-of-order arrivals (Waku gives no ordering) and ignoring
 * already-applied ones (idempotent). The tree must currently hold exactly
 * the leaves [0, tree.size).
 */
export class RegistrationSync {
	private buffer = new Map<number, Commitment>();

	constructor(
		private tree: MerkleTree,
		private onUpdate?: () => void,
	) {}

	ingest(msg: RegistrationMsg): void {
		if (msg.leafIndex < this.tree.size) return; // already applied
		this.buffer.set(msg.leafIndex, msg.commitment);
		this.drain();
	}

	private drain(): void {
		let applied = false;
		for (let next = this.buffer.get(this.tree.size); next !== undefined; next = this.buffer.get(this.tree.size)) {
			this.buffer.delete(this.tree.size);
			this.tree.append(next);
			applied = true;
		}
		if (applied) this.onUpdate?.();
	}
}

// ── Waku I/O ─────────────────────────────────────────────────────────

export class WakuTransport {
	private readonly t: ReturnType<typeof topics>;
	private readonly postEncoder: IEncoder;
	private readonly postDecoder: IDecoder<IDecodedMessage>;
	private readonly certEncoder: IEncoder;
	private readonly certDecoder: IDecoder<IDecodedMessage>;
	private readonly regEncoder: IEncoder;
	private readonly regDecoder: IDecoder<IDecodedMessage>;

	private constructor(
		private readonly node: LightNode,
		opts: TransportOptions,
	) {
		this.t = topics(opts.forumId);
		// Registrations are plaintext; the node derives routingInfo from its
		// network config. Reuse that routingInfo for the symmetric encoders.
		this.regEncoder = node.createEncoder({ contentTopic: this.t.reg });
		this.regDecoder = node.createDecoder({ contentTopic: this.t.reg });
		const routingInfo = this.regEncoder.routingInfo;
		this.postEncoder = createSymEncoder({ contentTopic: this.t.post, routingInfo, symKey: opts.forumKey });
		this.postDecoder = createSymDecoder(this.t.post, routingInfo, opts.forumKey);
		this.certEncoder = createSymEncoder({ contentTopic: this.t.cert, routingInfo, symKey: opts.forumKey });
		this.certDecoder = createSymDecoder(this.t.cert, routingInfo, opts.forumKey);
	}

	static async connect(opts: TransportOptions): Promise<WakuTransport> {
		const node = await createLightNode({ defaultBootstrap: false });
		await node.start();
		try {
			for (const peer of opts.peers) await node.dial(peer);
			await node.waitForPeers([Protocols.LightPush, Protocols.Filter, Protocols.Store]);
		} catch (e) {
			await node.stop();
			throw new ForumError("transport_error", `Waku connect failed: ${String(e)}`);
		}
		return new WakuTransport(node, opts);
	}

	async stop(): Promise<void> {
		await this.node.stop();
	}

	async publishPost(envelope: PostEnvelope): Promise<void> {
		await this.send(this.postEncoder, envelope);
	}

	async subscribePosts(onPost: (envelope: PostEnvelope) => void): Promise<void> {
		await this.node.filter.subscribe([this.postDecoder], (msg) => {
			if (msg.payload) onPost(decodeJson<PostEnvelope>(msg.payload));
		});
	}

	async publishCertificate(cert: ModerationCertificate): Promise<void> {
		await this.send(this.certEncoder, cert);
	}

	/** Fetch certs for a member identified by `nullifier` (ADR-009). Joins
	 *  the posts topic (contentId → nullifier) against the certs topic. */
	async listCertificatesByNullifier(nullifier: string): Promise<ModerationCertificate[]> {
		const [posts, certs] = await Promise.all([
			this.storeAll<PostEnvelope>(this.postDecoder),
			this.storeAll<ModerationCertificate>(this.certDecoder),
		]);
		return selectCertsForNullifier(posts, certs, nullifier);
	}

	async publishRegistration(msg: RegistrationMsg): Promise<void> {
		await this.node.lightPush.send(this.regEncoder, { payload: encodeJson(msg) });
	}

	/** Replay the registration topic from Store, then live-subscribe, applying
	 *  to `tree` in leafIndex order. After replay, the caller should assert
	 *  tree.root() === forum.treeRoot (sync correctness). */
	async syncRegistrations(tree: MerkleTree, onUpdate?: () => void): Promise<void> {
		const sync = new RegistrationSync(tree, onUpdate);
		const stored = await this.storeAll<RegistrationMsg>(this.regDecoder);
		stored.sort((a, b) => a.leafIndex - b.leafIndex).forEach((r) => sync.ingest(r));
		await this.node.filter.subscribe([this.regDecoder], (msg) => {
			if (msg.payload) sync.ingest(decodeJson<RegistrationMsg>(msg.payload));
		});
	}

	private async send(encoder: IEncoder, obj: unknown): Promise<void> {
		const res = await this.node.lightPush.send(encoder, { payload: encodeJson(obj) });
		if (res.failures && res.failures.length > 0) {
			throw new ForumError("transport_error", `Waku push failed: ${JSON.stringify(res.failures)}`);
		}
	}

	private async storeAll<T>(decoder: IDecoder<IDecodedMessage>): Promise<T[]> {
		const out: T[] = [];
		await this.node.store.queryWithOrderedCallback([decoder], (msg) => {
			if (msg.payload) out.push(decodeJson<T>(msg.payload));
		});
		return out;
	}
}
