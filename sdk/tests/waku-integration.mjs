// Live Waku round-trip against a local nwaku (run ON the box where nwaku
// runs — no tunnel). Verifies the transport layer end to end: filter
// delivery, Store join (listCertificatesByNullifier), and registration
// tree-sync. Pure Waku — no daemon/chain needed.
//
//   NWAKU_PEER=/ip4/127.0.0.1/tcp/60000/p2p/<peerId> node sdk/tests/waku-integration.mjs

import { generateSymmetricKey, MerkleTree, WakuTransport } from "../dist/index.js";

const NWAKU = process.env.NWAKU_PEER;
if (!NWAKU) {
	console.error("set NWAKU_PEER to the nwaku multiaddr");
	process.exit(1);
}

const hx = (b) => b.repeat(32);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function assert(cond, msg) {
	if (!cond) {
		console.error("FAIL:", msg);
		process.exit(1);
	}
	console.log("  ok:", msg);
}

const forumKey = generateSymmetricKey();
const forumId = `waku-int-${Date.now()}`;
const NULL = hx("aa");
const CID = hx("cc");

const t = await WakuTransport.connect({
	forumId,
	peers: [NWAKU],
	forumKey,
	clusterId: 2,
	numShardsInCluster: 8,
});
console.log("connected to nwaku");

// 1. Live delivery via Filter subscription.
const received = [];
await t.subscribePosts((e) => received.push(e));
await sleep(1500);
const envelope = {
	contentId: CID,
	epoch: 1,
	treeRoot: hx("00"),
	nullifier: NULL,
	shareX: hx("11"),
	shareY: hx("22"),
	receipt: "",
};
await t.publishPost(envelope);
await sleep(3000);
assert(
	received.some((e) => e.contentId === CID && e.nullifier === NULL),
	"post delivered via Filter subscription",
);

// 2. Store join: a cert + listCertificatesByNullifier.
await t.publishCertificate({ contentId: CID, strikeIndex: 0, shareX: hx("11"), shareY: hx("22"), signatures: [] });
await sleep(3000);
const certs = await t.listCertificatesByNullifier(NULL);
assert(
	certs.length === 1 && certs[0].contentId === CID,
	"listCertificatesByNullifier joins posts+certs from Store",
);

// 3. Registration tree-sync from Store (out-of-order publish).
await t.publishRegistration({ leafIndex: 1, commitment: hx("d2") });
await t.publishRegistration({ leafIndex: 0, commitment: hx("d1") });
await sleep(3000);
const tree = new MerkleTree();
await t.syncRegistrations(tree);
await sleep(1500);
assert(tree.size === 2, "tree synced 2 registrations from Store");
assert(
	tree.indexOf(hx("d1")) === 0 && tree.indexOf(hx("d2")) === 1,
	"registrations applied in leafIndex order despite out-of-order publish",
);

console.log("\nWAKU INTEGRATION OK");
await t.stop();
process.exit(0);
