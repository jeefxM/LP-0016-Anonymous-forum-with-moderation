// Reads witness.json, reconstructs the 256 output bits (signals 1..257) into
// a hex digest, and compares with the expected value passed as argv[2].
import { readFileSync } from "node:fs";

const expected = process.argv[2];
const w = JSON.parse(readFileSync(new URL("./witness.json", import.meta.url)));
const outBits = w.slice(1, 257).map(Number);

const bytes = Buffer.alloc(32);
for (let i = 0; i < 32; i++) {
	let b = 0;
	for (let j = 0; j < 8; j++) b = (b << 1) | outBits[i * 8 + j];
	bytes[i] = b;
}
const got = bytes.toString("hex");
console.log("CIRCUIT ", got);
console.log("EXPECTED", expected);
if (got === expected) {
	console.log("MATCH ✅ circomlib SHA-256 == standard SHA-256");
	process.exit(0);
}
console.error("MISMATCH ❌");
process.exit(1);
