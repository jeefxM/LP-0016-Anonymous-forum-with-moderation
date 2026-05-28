// Live integration check: drives the built SDK against a running proof
// daemon (tunnel localhost:8787 → Hetzner). Not a unit test — needs the
// daemon + live chain. Run: node sdk/tests/integration.mjs
//
// Validates that the SDK's request shapes match the daemon, that the local
// MerkleTree stays in sync with the chain root, and that a full
// register → post → verify → moderate flow works through SDK imports only.

import {
	aggregateCertificate,
	createForumInstance,
	createIdentity,
	createPostProof,
	isRevoked,
	loadForumInstance,
	MerkleTree,
	register,
	SDK_VERSION,
	signModerationVote,
	verifyPostProof,
} from "../dist/index.js";

const ZERO = "00".repeat(32);
const tree = new MerkleTree();
const config = { daemonUrl: "http://127.0.0.1:8787", tree };

function assert(cond, msg) {
	if (!cond) {
		console.error("FAIL:", msg);
		process.exit(1);
	}
	console.log("  ok:", msg);
}

const forumId = `sdk-int-${Date.now()}`;

// Bootstrap 3 moderator pubkeys (signModerationVote returns the pubkey).
const modSecrets = ["01", "02", "03"].map((b) => b.repeat(32));
const moderators = [];
for (const moderatorSecret of modSecrets) {
	const v = await signModerationVote(
		{ forum: null, moderatorSecret, envelope: { contentId: ZERO, shareX: ZERO, shareY: ZERO }, strikeIndex: 0 },
		config,
	);
	moderators.push(v.moderator);
}
console.log("moderators:", moderators);

const forum = await createForumInstance(
	{ forumId, moderators, nThreshold: 2, kThreshold: 3, stakeAmount: 1000n },
	config,
);
assert(typeof forum.stakeAmount === "bigint", "stakeAmount mapped to bigint");
assert(forum.nextLeafIndex === 0, "fresh forum at leaf 0");
assert(forum.treeRoot === tree.root(), "empty forum root matches local empty tree");

const id = await createIdentity(config);
console.log("identity commitment:", id.commitment);

const reg = await register(forum, id, config);
assert(reg.leafIndex === 0, "registered at leaf 0");
console.log("register tx:", reg.txHash);

const reloaded = await loadForumInstance(forumId, config);
assert(reloaded.nextLeafIndex === 1, "chain leaf index advanced to 1");
assert(reloaded.treeRoot === tree.root(), "local tree root matches chain after append");

assert((await isRevoked(reloaded, id.commitment, config)) === false, "member not revoked");

const env = await createPostProof(
	{ forum: reloaded, identity: id, contentId: "cc".repeat(32), epoch: 1 },
	config,
);
assert(env.treeRoot === reloaded.treeRoot, "envelope targets the current root");
console.log("post nullifier:", env.nullifier);

const ver = await verifyPostProof(reloaded, env, config);
assert(ver.valid === true, "post proof verifies");

const v1 = await signModerationVote(
	{ forum: reloaded, moderatorSecret: modSecrets[0], envelope: env, strikeIndex: 0 },
	config,
);
const v2 = await signModerationVote(
	{ forum: reloaded, moderatorSecret: modSecrets[1], envelope: env, strikeIndex: 0 },
	config,
);
const cert = await aggregateCertificate(reloaded, [v1, v2], config);
assert(cert.signatures.length === 2, "2-of-3 certificate aggregated");

console.log(`\nSDK ${SDK_VERSION} — LIVE INTEGRATION OK`);
