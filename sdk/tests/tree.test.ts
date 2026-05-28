import { describe, expect, it } from "vitest";
import { bytesToHex, MerkleTree, sha256, TREE_DEPTH } from "../src/tree";

const ZERO_HEX = "00".repeat(32);

// Cross-system anchor: this is what the live LEZ chain reports as the
// tree_root of a freshly-created (empty) forum instance — i.e. the Rust
// `empty_tree_root()` = fold_path(0, [0;16], 0). If the TS tree's hashing or
// folding convention drifts from Rust, this fails.
const EMPTY_TREE_ROOT = "34fc00e4cf4a4794a0c6c128808c4c45af3dac2c07b7fdf151b85114f2431d44";

const A = "aa".repeat(32);
const B = "bb".repeat(32);

describe("sha256", () => {
	it("matches the FIPS-180-4 'abc' vector", () => {
		const out = bytesToHex(sha256(new Uint8Array([0x61, 0x62, 0x63])));
		expect(out).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	});

	it("hashes the empty string", () => {
		const out = bytesToHex(sha256(new Uint8Array([])));
		expect(out).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	});
});

describe("MerkleTree", () => {
	it("empty root equals the live-chain empty_tree_root", () => {
		expect(new MerkleTree().root()).toBe(EMPTY_TREE_ROOT);
	});

	it("append assigns sequential indices and tracks size", () => {
		const t = new MerkleTree();
		expect(t.append(A)).toBe(0);
		expect(t.append(B)).toBe(1);
		expect(t.size).toBe(2);
		expect(t.indexOf(A)).toBe(0);
		expect(t.indexOf(B)).toBe(1);
		expect(t.indexOf("cc".repeat(32))).toBe(-1);
	});

	it("inserting a leaf advances the root", () => {
		const t = new MerkleTree();
		const before = t.root();
		t.append(A);
		expect(t.root()).not.toBe(before);
	});

	it("pathBits equals the leaf index", () => {
		const t = new MerkleTree();
		expect(t.pathBits(0)).toBe(0);
		expect(t.pathBits(1)).toBe(1);
		expect(t.pathBits(5)).toBe(5);
	});

	it("leaf 0 in a singleton tree has an all-zero sibling path", () => {
		const t = new MerkleTree();
		t.append(A);
		const sib = t.siblings(0);
		expect(sib).toHaveLength(TREE_DEPTH);
		expect(sib.every((h) => h === ZERO_HEX)).toBe(true);
	});

	it("path_before for leaf 1 is [leaf0, 0, 0, ...] (matches Rust)", () => {
		const t = new MerkleTree();
		t.append(A); // tree now has exactly 1 leaf → siblings(1) is the insert path
		const path = t.siblings(1);
		expect(path[0]).toBe(A);
		expect(path.slice(1).every((h) => h === ZERO_HEX)).toBe(true);
		expect(t.pathBits(1)).toBe(1);
	});

	it("leaf 0's sibling becomes leaf 1 once leaf 1 is added", () => {
		const t = new MerkleTree();
		t.append(A);
		expect(t.siblings(0)[0]).toBe(ZERO_HEX);
		t.append(B);
		// n(1,0) = H(A,B), so leaf 0's level-0 sibling is now B.
		expect(t.siblings(0)[0]).toBe(B);
	});
});
