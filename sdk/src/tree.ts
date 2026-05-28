// Incremental membership Merkle tree, mirroring the Rust convention shared
// by the post_proof guest, membership_registry, and slash-evidence:
//
//   - the leaf IS the commitment (no extra leaf hashing)
//   - node_hash(l, r) = SHA-256("node" || l || r)
//   - the empty value at every level is 32 zero bytes (a fixed-zero sparse
//     tree, NOT recursive empty-subtree hashing) — so an absent sibling is
//     0x00*32, exactly what `Instruction::Register`'s `path_before` expects.
//   - merkle_path_bits is just the leaf index (bit L selects orientation).
//
// The SDK owns this because the daemon is stateless about the tree
// (ADR-004): the SDK computes `pathBefore` for register and the membership
// `siblings`/`pathBits` for createPostProof, then passes them to the daemon.
//
// SHA-256 is vendored (below) to keep the SDK dependency-free and usable in
// any JS runtime. It only ever hashes public commitments — no secrets.

export const TREE_DEPTH = 16;
export const MAX_LEAVES = 1 << TREE_DEPTH;

const NODE_TAG = new Uint8Array([0x6e, 0x6f, 0x64, 0x65]); // "node"
const ZERO = new Uint8Array(32);

export function hexToBytes(hex: string): Uint8Array {
	if (hex.length % 2 !== 0) throw new Error(`odd-length hex: ${hex}`);
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) {
		const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
		if (Number.isNaN(byte)) throw new Error(`bad hex: ${hex}`);
		out[i] = byte;
	}
	return out;
}

export function bytesToHex(bytes: Uint8Array): string {
	let s = "";
	for (const b of bytes) s += b.toString(16).padStart(2, "0");
	return s;
}

function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
	const buf = new Uint8Array(NODE_TAG.length + 64);
	buf.set(NODE_TAG, 0);
	buf.set(left, NODE_TAG.length);
	buf.set(right, NODE_TAG.length + 32);
	return sha256(buf);
}

/** An append-only membership tree. Leaves are 32-byte commitments (hex). */
export class MerkleTree {
	private leaves: Uint8Array[] = [];

	/** Number of leaves currently in the tree. */
	get size(): number {
		return this.leaves.length;
	}

	/** Append a commitment leaf; returns its index. */
	append(commitmentHex: string): number {
		if (this.leaves.length >= MAX_LEAVES) throw new Error("tree is full");
		const leaf = hexToBytes(commitmentHex);
		if (leaf.length !== 32) throw new Error("commitment must be 32 bytes");
		this.leaves.push(leaf);
		return this.leaves.length - 1;
	}

	/** Index of a commitment, or -1 if absent. */
	indexOf(commitmentHex: string): number {
		const target = hexToBytes(commitmentHex);
		for (let i = 0; i < this.leaves.length; i++) {
			if (eqBytes(this.leaves[i] as Uint8Array, target)) return i;
		}
		return -1;
	}

	/** Current Merkle root (hex). */
	root(): string {
		return bytesToHex(this.node(TREE_DEPTH, 0));
	}

	/**
	 * Sibling hashes (hex) from leaf level up to the root for `index`,
	 * computed against the tree as it currently stands. Used two ways:
	 *   - membership proof for an existing leaf (tree contains it)
	 *   - `path_before` for the next insertion (call with size === index)
	 */
	siblings(index: number): string[] {
		const out: string[] = [];
		for (let level = 0; level < TREE_DEPTH; level++) {
			const sibPos = (index >> level) ^ 1;
			out.push(bytesToHex(this.node(level, sibPos)));
		}
		return out;
	}

	/** merkle_path_bits for `index` — identical to the index for depth ≤ 32. */
	pathBits(index: number): number {
		return index >>> 0;
	}

	/**
	 * Value of the node at (level, pos).
	 *
	 * Matches the Rust `fold_path` convention, where the empty value at every
	 * level is the 0x00*32 constant (a fixed-zero sparse tree). Two cases:
	 *   - A leaf is its commitment, or 0x00*32 if that position is unfilled.
	 *   - A *right* sibling subtree (pos > 0) that holds no leaf collapses to
	 *     0x00*32 — that's the zero sibling `path_before` supplies.
	 * The leftmost spine (pos == 0) is never collapsed: it always folds down
	 * to a zero leaf, so an empty tree's root is `fold_path(0, zeros, 0)`
	 * (a nonzero hash chain) rather than 0x00*32.
	 */
	private node(level: number, pos: number): Uint8Array {
		if (level === 0) return pos < this.leaves.length ? (this.leaves[pos] as Uint8Array) : ZERO;
		if (pos > 0 && pos * 2 ** level >= this.leaves.length) return ZERO;
		return nodeHash(this.node(level - 1, 2 * pos), this.node(level - 1, 2 * pos + 1));
	}
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

// ── Vendored SHA-256 (FIPS 180-4) ────────────────────────────────────
// Sync, dependency-free, operates on Uint8Array. Hash-only (no secrets).

const K = new Uint32Array([
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
	return (x >>> n) | (x << (32 - n));
}

export function sha256(message: Uint8Array): Uint8Array {
	const h = new Uint32Array([
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	]);

	const bitLen = message.length * 8;
	const padded = new Uint8Array((((message.length + 8) >> 6) + 1) << 6);
	padded.set(message);
	padded[message.length] = 0x80;
	const view = new DataView(padded.buffer);
	// 64-bit length, big-endian (high word is 0 for our small inputs).
	view.setUint32(padded.length - 4, bitLen >>> 0, false);
	view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000), false);

	const w = new Uint32Array(64);
	for (let off = 0; off < padded.length; off += 64) {
		for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
		for (let i = 16; i < 64; i++) {
			const w15 = w[i - 15] as number;
			const w2 = w[i - 2] as number;
			const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
			const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
			w[i] = ((w[i - 16] as number) + s0 + (w[i - 7] as number) + s1) >>> 0;
		}

		let a = h[0] as number;
		let b = h[1] as number;
		let c = h[2] as number;
		let d = h[3] as number;
		let e = h[4] as number;
		let f = h[5] as number;
		let g = h[6] as number;
		let hh = h[7] as number;

		for (let i = 0; i < 64; i++) {
			const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = (e & f) ^ (~e & g);
			const t1 = (hh + S1 + ch + (K[i] as number) + (w[i] as number)) >>> 0;
			const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const t2 = (S0 + maj) >>> 0;
			hh = g;
			g = f;
			f = e;
			e = (d + t1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (t1 + t2) >>> 0;
		}

		h[0] = ((h[0] as number) + a) >>> 0;
		h[1] = ((h[1] as number) + b) >>> 0;
		h[2] = ((h[2] as number) + c) >>> 0;
		h[3] = ((h[3] as number) + d) >>> 0;
		h[4] = ((h[4] as number) + e) >>> 0;
		h[5] = ((h[5] as number) + f) >>> 0;
		h[6] = ((h[6] as number) + g) >>> 0;
		h[7] = ((h[7] as number) + hh) >>> 0;
	}

	const out = new Uint8Array(32);
	const outView = new DataView(out.buffer);
	for (let i = 0; i < 8; i++) outView.setUint32(i * 4, h[i] as number, false);
	return out;
}
