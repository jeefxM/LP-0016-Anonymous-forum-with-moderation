// Writes input.json (544 MSB-first bits of "node"‖l‖r) and prints the
// expected standard SHA-256 digest.
import crypto from "node:crypto";
import { writeFileSync } from "node:fs";

const l = Buffer.alloc(32, 0x01);
const r = Buffer.alloc(32, 0x02);
const pre = Buffer.concat([Buffer.from("node"), l, r]); // 68 bytes

const bits = [];
for (const byte of pre) for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);

writeFileSync(new URL("./input.json", import.meta.url), JSON.stringify({ in: bits.map(String) }));
console.log("EXPECTED", crypto.createHash("sha256").update(pre).digest("hex"));
