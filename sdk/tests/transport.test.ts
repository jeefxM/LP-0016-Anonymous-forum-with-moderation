import { describe, expect, it } from "vitest";
import { MerkleTree } from "../src/tree";
import { RegistrationSync, selectCertsForNullifier } from "../src/transport";
import type { ModerationCertificate, PostEnvelope } from "../src/types";

const hx = (b: string) => b.repeat(32);

function post(contentId: string, nullifier: string): PostEnvelope {
	return {
		contentId,
		epoch: 1,
		treeRoot: hx("00"),
		nullifier,
		shareX: hx("11"),
		shareY: hx("22"),
		receipt: "",
	};
}

function cert(contentId: string): ModerationCertificate {
	return { contentId, strikeIndex: 0, shareX: hx("11"), shareY: hx("22"), signatures: [] };
}

describe("selectCertsForNullifier", () => {
	it("returns certs whose post shares the target nullifier", () => {
		const N1 = hx("aa");
		const N2 = hx("bb");
		const posts = [post(hx("01"), N1), post(hx("02"), N1), post(hx("03"), N2)];
		const certs = [cert(hx("01")), cert(hx("02")), cert(hx("03"))];
		const got = selectCertsForNullifier(posts, certs, N1).map((c) => c.contentId);
		expect(got.sort()).toEqual([hx("01"), hx("02")].sort());
	});

	it("dedupes to one cert per contentId", () => {
		const N = hx("aa");
		const posts = [post(hx("01"), N)];
		const certs = [cert(hx("01")), cert(hx("01"))];
		expect(selectCertsForNullifier(posts, certs, N)).toHaveLength(1);
	});

	it("returns empty when no post matches", () => {
		const posts = [post(hx("01"), hx("aa"))];
		expect(selectCertsForNullifier(posts, [cert(hx("01"))], hx("ff"))).toHaveLength(0);
	});
});

describe("RegistrationSync", () => {
	it("applies in-order registrations", () => {
		const tree = new MerkleTree();
		let updates = 0;
		const sync = new RegistrationSync(tree, () => updates++);
		sync.ingest({ leafIndex: 0, commitment: hx("01") });
		sync.ingest({ leafIndex: 1, commitment: hx("02") });
		expect(tree.size).toBe(2);
		expect(tree.indexOf(hx("01"))).toBe(0);
		expect(updates).toBe(2);
	});

	it("buffers out-of-order arrivals then drains when the gap fills", () => {
		const tree = new MerkleTree();
		const sync = new RegistrationSync(tree);
		sync.ingest({ leafIndex: 2, commitment: hx("03") });
		sync.ingest({ leafIndex: 1, commitment: hx("02") });
		expect(tree.size).toBe(0); // still waiting for leaf 0
		sync.ingest({ leafIndex: 0, commitment: hx("01") });
		expect(tree.size).toBe(3); // 0 fills the gap, 1 and 2 drain
		expect(tree.indexOf(hx("03"))).toBe(2);
	});

	it("ignores already-applied registrations (idempotent)", () => {
		const tree = new MerkleTree();
		const sync = new RegistrationSync(tree);
		sync.ingest({ leafIndex: 0, commitment: hx("01") });
		sync.ingest({ leafIndex: 0, commitment: hx("99") }); // duplicate / echo of own publish
		expect(tree.size).toBe(1);
		expect(tree.indexOf(hx("01"))).toBe(0);
		expect(tree.indexOf(hx("99"))).toBe(-1);
	});
});
