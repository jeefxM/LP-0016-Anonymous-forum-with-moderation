// Correctness gate (PERF-3): feed the Rust oracle's inputs through the
// circuit and check nullifier/shareX/shareY match byte-for-byte.
// Reads /tmp/oracle.txt (key=hexvalue lines). Requires membership.{wasm,sym}.
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const oracle = Object.fromEntries(
	readFileSync("/tmp/oracle.txt", "utf8")
		.trim()
		.split("\n")
		.map((l) => {
			const i = l.indexOf("=");
			return [l.slice(0, i), l.slice(i + 1)];
		}),
);
const hexToBytes = (h) => Array.from(Buffer.from(h, "hex"));

const input = {
	secret: hexToBytes(oracle.secret).map(String),
	siblings: Array.from({ length: 16 }, (_, i) => hexToBytes(oracle[`sib${i}`]).map(String)),
	pathBits: "0",
	treeRoot: hexToBytes(oracle.treeRoot).map(String),
	epoch: oracle.epoch,
	contentId: hexToBytes(oracle.contentId).map(String),
};
writeFileSync("input.json", JSON.stringify(input));

execSync("node membership_js/generate_witness.js membership_js/membership.wasm input.json witness.wtns", {
	stdio: "inherit",
});

// Parse witness.wtns binary directly (the JSON export is >512MB).
const buf = readFileSync("witness.wtns");
const nSections = buf.readUInt32LE(8);
let o = 12;
let n8 = 32;
let dataOff = 0;
for (let s = 0; s < nSections; s++) {
	const id = buf.readUInt32LE(o);
	o += 4;
	const len = Number(buf.readBigUInt64LE(o));
	o += 8;
	if (id === 1) n8 = buf.readUInt32LE(o);
	if (id === 2) dataOff = o;
	o += len;
}
// Output signals are byte-valued (< 256), so the low byte of each LE field
// element is the value.
const witByte = (i) => buf[dataOff + i * n8];

// The .sym is huge; grep only the output-signal lines.
const idxOf = {};
const symLines = execSync("grep -E 'main\\.(nullifier|shareX|shareY)\\[' membership.sym")
	.toString()
	.trim()
	.split("\n");
for (const line of symLines) {
	const [, wi, , name] = line.split(",");
	idxOf[name] = Number(wi);
}
const readBytes = (prefix) => {
	const out = Buffer.alloc(32);
	for (let j = 0; j < 32; j++) out[j] = witByte(idxOf[`main.${prefix}[${j}]`]);
	return out.toString("hex");
};

let ok = true;
for (const f of ["nullifier", "shareX", "shareY"]) {
	const got = readBytes(f);
	const exp = oracle[f];
	const match = got === exp;
	ok = ok && match;
	console.log(`${f}: ${match ? "MATCH ✅" : `MISMATCH ❌\n  got=${got}\n  exp=${exp}`}`);
}
process.exit(ok ? 0 : 1);
