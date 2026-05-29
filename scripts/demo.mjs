#!/usr/bin/env node
// LP-0016 — reproducible end-to-end demo.
//
// Runs the full anonymous-forum lifecycle through the SDK against the live
// local stack:
//   create instance → register (stake) → post (Groth16 membership proof)
//   → N-of-M moderation → K strikes → slash → revoke.
//
// Real proofs: chain transactions (register, slash) are executed and proven
// by the standalone LEZ sequencer with RISC0_DEV_MODE=0 — real STARK proofs,
// not dev-mode receipts. The membership post-proof is Groth16 (rapidsnark).
//
// Prerequisites — bring the backend up first (see docs/deployments.md
// "Restarting the local chain" and app/README.md "Run it"):
//   - LEZ sequencer (standalone, RISC0_DEV_MODE=0) + bedrock node
//   - proof daemon listening on DAEMON_URL (default http://127.0.0.1:8787)
//   - nwaku; pass its /ws multiaddr in NWAKU_PEER
//
// Run on the backend box:
//   NWAKU_PEER=/ip4/127.0.0.1/tcp/8000/ws/p2p/<peerId> node scripts/demo.mjs
//   # or, from the repo root: just demo

const DAEMON_URL = process.env.DAEMON_URL ?? "http://127.0.0.1:8787";
const NWAKU_PEER = process.env.NWAKU_PEER;

function die(msg) {
	console.error(`\n✗ ${msg}\n`);
	console.error("This demo runs the full lifecycle against a live backend.");
	console.error("Bring it up first, then re-run. See:");
	console.error("  docs/deployments.md  (§ Restarting the local chain)");
	console.error("  app/README.md        (§ Run it)");
	process.exit(1);
}

console.log("──────────────────────────────────────────────────────────────");
console.log(" LP-0016 — anonymous forum: full lifecycle demo");
console.log(" register → post → N-of-M moderate → K strikes → slash → revoke");
console.log(" Real proofs: sequencer RISC0_DEV_MODE=0 + Groth16 membership proof");
console.log("──────────────────────────────────────────────────────────────");

if (!NWAKU_PEER) die("NWAKU_PEER is not set (nwaku /ws multiaddr).");

try {
	const r = await fetch(`${DAEMON_URL}/v1/health`, {
		signal: AbortSignal.timeout(5000),
	});
	if (!r.ok) die(`proof daemon at ${DAEMON_URL} returned HTTP ${r.status}`);
	console.log(`✓ proof daemon ${DAEMON_URL} — ${JSON.stringify(await r.json())}`);
} catch (e) {
	die(`proof daemon at ${DAEMON_URL} is unreachable (${e?.message ?? e}).`);
}
console.log(`✓ nwaku peer ${NWAKU_PEER}\n`);

// The lifecycle flow is shared with sdk/tests/lifecycle.mjs (the SDK
// integration reference): it drives every step through SDK imports only and
// asserts each invariant, exiting non-zero on any failure.
await import("../sdk/tests/lifecycle.mjs");
