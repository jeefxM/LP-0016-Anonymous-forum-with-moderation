import { afterEach, describe, expect, it, vi } from "vitest";
import { daemonPost } from "../src/client";
import { ForumError } from "../src/types";

afterEach(() => {
	vi.unstubAllGlobals();
});

function stubFetch(impl: typeof fetch) {
	vi.stubGlobal("fetch", impl);
}

describe("daemonPost", () => {
	it("returns parsed JSON on success", async () => {
		stubFetch(async () => new Response(JSON.stringify({ revoked: true }), { status: 200 }));
		const out = await daemonPost<{ revoked: boolean }>(undefined, "/v1/member/is-revoked", {});
		expect(out.revoked).toBe(true);
	});

	it("maps a daemon error body to a typed ForumError", async () => {
		stubFetch(
			async () =>
				new Response(JSON.stringify({ kind: "below_threshold", message: "need 3 certs" }), {
					status: 422,
				}),
		);
		await expect(daemonPost(undefined, "/v1/moderation/aggregate", {})).rejects.toMatchObject({
			name: "ForumError",
			kind: "below_threshold",
			message: "need 3 certs",
		});
	});

	it("maps not_found", async () => {
		stubFetch(
			async () => new Response(JSON.stringify({ kind: "not_found", message: "no forum" }), { status: 404 }),
		);
		await expect(daemonPost(undefined, "/v1/forum/load", {})).rejects.toMatchObject({
			kind: "not_found",
		});
	});

	it("falls back to chain_error for an unknown error kind", async () => {
		stubFetch(async () => new Response(JSON.stringify({ kind: "weird", message: "x" }), { status: 500 }));
		await expect(daemonPost(undefined, "/v1/forum/load", {})).rejects.toMatchObject({
			kind: "chain_error",
		});
	});

	it("reports daemon_unreachable when fetch throws", async () => {
		stubFetch(async () => {
			throw new Error("ECONNREFUSED");
		});
		const err = await daemonPost(undefined, "/v1/health", {}).catch((e) => e);
		expect(err).toBeInstanceOf(ForumError);
		expect(err.kind).toBe("daemon_unreachable");
	});
});
