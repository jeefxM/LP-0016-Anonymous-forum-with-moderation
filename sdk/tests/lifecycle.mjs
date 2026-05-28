// P6.5 — full lifecycle through SDK imports ONLY, against a live daemon
// (chain + proof) and a live nwaku (transport). Run ON the box where both
// run (no tunnels):
//
//   NWAKU_PEER=/ip4/127.0.0.1/tcp/8000/ws/p2p/<peerId> \
//   DAEMON_URL=http://127.0.0.1:8787 node sdk/tests/lifecycle.mjs
//
// Flow: create forum -> register -> K posts (same epoch => same nullifier,
// distinct shares) -> publish posts + N-of-M certs to Waku -> gather certs
// by nullifier -> reconstruct slash evidence -> submit slash -> member is
// revoked. Also checks registration tree-sync into a second tree.

import {
	aggregateCertificate,
	createForumInstance,
	createIdentity,
	createPostProof,
	generateSymmetricKey,
	isRevoked,
	listCertificatesByNullifier,
	loadForumInstance,
	MerkleTree,
	publishCertificate,
	publishPost,
	register,
	signModerationVote,
	submitSlash,
	subscribeRegistrations,
	tryReconstructSlashEvidence,
	verifyPostProof,
	WakuTransport,
} from "../dist/index.js";

const NWAKU = process.env.NWAKU_PEER;
const daemonUrl = process.env.DAEMON_URL ?? "http://127.0.0.1:8787";
if (!NWAKU) {
	console.error("set NWAKU_PEER");
	process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function assert(cond, msg) {
	if (!cond) {
		console.error("FAIL:", msg);
		process.exit(1);
	}
	console.log("  ok:", msg);
}

const K = 3;
const N = 2;
const EPOCH = 1;
const forumId = `life-${Date.now()}`;
const forumKey = generateSymmetricKey();
const tree = new MerkleTree();

const transport = await WakuTransport.connect({
	forumId,
	peers: [NWAKU],
	forumKey,
	clusterId: 2,
	numShardsInCluster: 8,
});
const config = { daemonUrl, tree, transport };
console.log("connected to daemon + nwaku");

// Moderators: derive 3 pubkeys from fixed seeds (signModerationVote echoes
// the pubkey).
const modSecrets = ["a1", "b2", "c3"].map((b) => b.repeat(32));
const Z = "00".repeat(32);
const moderators = [];
for (const moderatorSecret of modSecrets) {
	const v = await signModerationVote(
		{ forum: null, moderatorSecret, envelope: { contentId: Z, shareX: Z, shareY: Z }, strikeIndex: 0 },
		config,
	);
	moderators.push(v.moderator);
}

// 1. Create forum + register a member.
const created = await createForumInstance(
	{ forumId, moderators, nThreshold: N, kThreshold: K, stakeAmount: 1000n },
	config,
);
assert(created.treeRoot === tree.root(), "fresh forum root matches empty tree");

const identity = await createIdentity(config);
const reg = await register(created, identity, config);
assert(reg.leafIndex === 0, "member registered at leaf 0");

const forum = await loadForumInstance(forumId, config);
assert(forum.nextLeafIndex === 1 && forum.treeRoot === tree.root(), "tree in sync with chain after register");

// Bonus: a second tree rebuilds itself from the Waku registration topic.
await sleep(2500);
const tree2 = new MerkleTree();
await subscribeRegistrations(forum, { ...config, tree: tree2 });
await sleep(2000);
assert(tree2.size === 1 && tree2.root() === forum.treeRoot, "second tree synced registration from Waku");

// 2. K posts in one epoch (same nullifier, distinct shares) + N-of-M certs.
const contentIds = ["11", "22", "33"].map((b) => b.repeat(32));
let nullifier;
for (let i = 0; i < K; i++) {
	const envelope = await createPostProof(
		{ forum, identity, contentId: contentIds[i], epoch: EPOCH },
		config,
	);
	nullifier ??= envelope.nullifier;
	assert(envelope.nullifier === nullifier, `post ${i} shares the member's epoch nullifier`);
	await publishPost(forum, envelope, config);

	if (i === 0) {
		const v = await verifyPostProof(forum, envelope, config);
		assert(v.valid === true, "first post proof verifies");
	}

	const votes = [];
	for (let m = 0; m < N; m++) {
		votes.push(
			await signModerationVote(
				{ forum, moderatorSecret: modSecrets[m], envelope, strikeIndex: i },
				config,
			),
		);
	}
	const cert = await aggregateCertificate(forum, votes, config);
	await publishCertificate(forum, cert, config);
}
console.log(`  published ${K} posts + ${K} certs (nullifier ${nullifier.slice(0, 12)}…)`);

// 3. Gather certs by nullifier, reconstruct, slash.
await sleep(3000);
const certs = await listCertificatesByNullifier(forum, nullifier, config);
assert(certs.length === K, `gathered ${K} certs by nullifier from Waku`);

const evidence = await tryReconstructSlashEvidence(forum, nullifier, config);
assert(evidence !== null, "slash evidence reconstructed");
assert(evidence.commitment === identity.commitment, "reconstructed commitment matches the member");

const slashTx = await submitSlash(forum, evidence, config);
console.log("  slash tx:", slashTx.txHash);

const after = await loadForumInstance(forumId, config);
assert(await isRevoked(after, identity.commitment, config), "member is revoked after slash");

console.log("\nFULL LIFECYCLE OK");
await transport.stop();
process.exit(0);
