// Typed HTTP client for the local proof daemon (ADR-004). Every SDK call
// that touches proving or the chain goes through `daemonPost`. Daemon
// errors arrive as `{ kind, message }` and are mapped back to a typed
// `ForumError`; a network failure becomes `daemon_unreachable`.

import { ForumError } from "./types.js";
import type { ForumErrorKind } from "./types.js";

export const DEFAULT_DAEMON_URL = "http://127.0.0.1:8787";

// Daemon error `kind` (snake_case) → SDK `ForumErrorKind`. The daemon never
// emits `daemon_unreachable` or `transport_error` (those are client-side).
const KIND_MAP: Record<string, ForumErrorKind> = {
	bad_request: "bad_request",
	proof_failed: "proof_failed",
	invalid_proof: "invalid_proof",
	revoked: "revoked",
	below_threshold: "below_threshold",
	chain_error: "chain_error",
	not_found: "not_found",
};

export async function daemonPost<T>(
	daemonUrl: string | undefined,
	path: string,
	body: unknown,
): Promise<T> {
	const url = (daemonUrl ?? DEFAULT_DAEMON_URL) + path;

	let res: Response;
	try {
		res = await fetch(url, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
	} catch (e) {
		throw new ForumError("daemon_unreachable", `cannot reach proof daemon at ${url}: ${String(e)}`);
	}

	const text = await res.text();
	if (!res.ok) {
		let kind: ForumErrorKind = "chain_error";
		let message = text || `daemon returned HTTP ${res.status}`;
		try {
			const parsed = JSON.parse(text) as { kind?: string; message?: string };
			const mapped = parsed.kind ? KIND_MAP[parsed.kind] : undefined;
			if (mapped) kind = mapped;
			if (parsed.message) message = parsed.message;
		} catch {
			// Non-JSON body — keep the raw text as the message.
		}
		throw new ForumError(kind, message);
	}

	return JSON.parse(text) as T;
}
