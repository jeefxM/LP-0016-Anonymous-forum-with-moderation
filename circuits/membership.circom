pragma circom 2.1.6;

// Anonymous membership post-proof (ADR-010). Replaces the risc0 post_proof
// guest with a Groth16 circuit, byte-for-byte matching the SHA-256 Rust
// stack (post_proof_core). Proves:
//   - commitment = SHA256("commit"||secret) is in the SHA-256 Merkle tree
//     with root `treeRoot` (16 levels, node = SHA256("node"||l||r));
//   - nullifier = SHA256("null"||secret||epoch_LE);
//   - shareX = from_le_bytes_mod_order(SHA256("shamir/x"||secret||contentId));
//   - shareY = Horner(coeffs, shareX) over BN254 Fr, where
//       coeff[0] = secret (as Fr),
//       coeff[i] = from_le_bytes_mod_order(SHA256("shamir/coeff"||secret||i_LE_u32)).
//
// Key trick (ADR-010 mod-r gadget): from_le_bytes_mod_order is just the
// field linear combination Σ bit·2^k — circom evaluates 2^k mod r, so the
// sum *is* the reduction. No quotient witness.

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";

// ── helpers ──────────────────────────────────────────────────────────

// One byte (range-checked < 256) -> 8 bits, MSB-first (bit[0] = MSB).
template ByteToBitsMSB() {
    signal input b;
    signal output bits[8];
    component n2b = Num2Bits(8); // LSB-first, enforces b < 2^8
    n2b.in <== b;
    for (var i = 0; i < 8; i++) { bits[i] <== n2b.out[7 - i]; }
}

// SHA-256 over `tagLen` constant tag bytes followed by `byteLen` input bytes.
// Returns the 256 output bits (MSB-first per byte), as circomlib emits them.
template Sha256Tagged(tagLen, byteLen) {
    signal input tag[tagLen];     // constant byte values
    signal input inBytes[byteLen];
    signal output out[256];

    var L = tagLen + byteLen;
    component h = Sha256(L * 8);

    // tag bytes (caller constrains them to constants) -> MSB-first bits
    component tb[tagLen];
    for (var j = 0; j < tagLen; j++) {
        tb[j] = ByteToBitsMSB();
        tb[j].b <== tag[j];
        for (var i = 0; i < 8; i++) { h.in[j * 8 + i] <== tb[j].bits[i]; }
    }
    component b2b[byteLen];
    for (var j = 0; j < byteLen; j++) {
        b2b[j] = ByteToBitsMSB();
        b2b[j].b <== inBytes[j];
        for (var i = 0; i < 8; i++) { h.in[(tagLen + j) * 8 + i] <== b2b[j].bits[i]; }
    }
    for (var k = 0; k < 256; k++) { out[k] <== h.out[k]; }
}

// node_hash = SHA256("node"(4) ‖ left(256 bits) ‖ right(256 bits)).
// left/right are already 256 bits MSB-first (SHA outputs / leaf bits).
template NodeHashBits() {
    signal input left[256];
    signal input right[256];
    signal output out[256];

    var tag[4] = [0x6e, 0x6f, 0x64, 0x65]; // "node"
    component h = Sha256(544); // (4 + 32 + 32) * 8
    for (var j = 0; j < 4; j++) {
        for (var i = 0; i < 8; i++) { h.in[j * 8 + i] <== (tag[j] >> (7 - i)) & 1; }
    }
    for (var k = 0; k < 256; k++) { h.in[32 + k] <== left[k]; }
    for (var k = 0; k < 256; k++) { h.in[32 + 256 + k] <== right[k]; }
    for (var k = 0; k < 256; k++) { out[k] <== h.out[k]; }
}

// SHA-256 output bits (MSB-first per byte) -> field element,
// = (the 32 bytes read little-endian as an integer) mod r.
//   byte j bit i (LSB i) = out[8j + (7 - i)]; weight 2^(8j+i).
template Sha256OutToField() {
    signal input out[256];
    signal output f;
    signal acc[257];
    acc[0] <== 0;
    for (var j = 0; j < 32; j++) {
        for (var i = 0; i < 8; i++) {
            var k = 8 * j + i;
            acc[k + 1] <== acc[k] + out[8 * j + (7 - i)] * (2 ** (8 * j + i));
        }
    }
    f <== acc[256];
}

// Little-endian bytes -> field element = (bytes as LE integer) mod r.
template LeBytesToField(n) {
    signal input bytes[n];
    signal output f;
    signal acc[n + 1];
    acc[0] <== 0;
    for (var j = 0; j < n; j++) { acc[j + 1] <== acc[j] + bytes[j] * (256 ** j); }
    f <== acc[n];
}

// Field element (< r) -> 32 little-endian bytes (fr_to_bytes).
template FieldToLeBytes() {
    signal input f;
    signal output bytes[32];
    component n2b = Num2Bits(254); // canonical value < r < 2^254
    n2b.in <== f;
    for (var j = 0; j < 32; j++) {
        var lc = 0;
        for (var i = 0; i < 8; i++) {
            var bit = j * 8 + i;
            if (bit < 254) { lc += n2b.out[bit] * (2 ** i); }
        }
        bytes[j] <== lc;
    }
}

// ── main circuit ─────────────────────────────────────────────────────

template Membership(TREE_DEPTH, K) {
    // private
    signal input secret[32];                 // 32 LE bytes, canonical Fr
    signal input siblings[TREE_DEPTH][32];   // 32 bytes each
    signal input pathBits;                    // < 2^TREE_DEPTH

    // public inputs
    signal input treeRoot[32];
    signal input epoch;                       // < 2^64
    signal input contentId[32];

    // public outputs
    signal output nullifier[32];
    signal output shareX[32];
    signal output shareY[32];

    // secret bits MSB-first (reused across hashes)
    component secretBits[32];
    for (var j = 0; j < 32; j++) {
        secretBits[j] = ByteToBitsMSB();
        secretBits[j].b <== secret[j];
    }

    // 1. commitment = SHA256("commit"(6) || secret)
    component commit = Sha256Tagged(6, 32);
    var commitTag[6] = [0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74]; // "commit"
    for (var j = 0; j < 6; j++) { commit.tag[j] <== commitTag[j]; }
    for (var j = 0; j < 32; j++) { commit.inBytes[j] <== secret[j]; }

    // 2. Merkle path: cur starts at commitment bits.
    component bits = Num2Bits(TREE_DEPTH);
    bits.in <== pathBits;

    component sibBits[TREE_DEPTH][32];
    component node[TREE_DEPTH];
    signal sibFull[TREE_DEPTH][256];
    signal cur[TREE_DEPTH + 1][256];
    for (var k = 0; k < 256; k++) { cur[0][k] <== commit.out[k]; }

    for (var lvl = 0; lvl < TREE_DEPTH; lvl++) {
        // sibling bytes -> 256 bits MSB-first
        for (var j = 0; j < 32; j++) {
            sibBits[lvl][j] = ByteToBitsMSB();
            sibBits[lvl][j].b <== siblings[lvl][j];
            for (var i = 0; i < 8; i++) { sibFull[lvl][j * 8 + i] <== sibBits[lvl][j].bits[i]; }
        }
        // bit==0: node(cur, sib); bit==1: node(sib, cur)
        node[lvl] = NodeHashBits();
        for (var k = 0; k < 256; k++) {
            node[lvl].left[k] <== cur[lvl][k] + bits.out[lvl] * (sibFull[lvl][k] - cur[lvl][k]);
            node[lvl].right[k] <== sibFull[lvl][k] + bits.out[lvl] * (cur[lvl][k] - sibFull[lvl][k]);
        }
        for (var k = 0; k < 256; k++) { cur[lvl + 1][k] <== node[lvl].out[k]; }
    }

    // constrain computed root == treeRoot (compare bit-for-bit)
    component rootBits[32];
    for (var j = 0; j < 32; j++) {
        rootBits[j] = ByteToBitsMSB();
        rootBits[j].b <== treeRoot[j];
        for (var i = 0; i < 8; i++) { cur[TREE_DEPTH][j * 8 + i] === rootBits[j].bits[i]; }
    }

    // 3. nullifier = SHA256("null"(4) || secret || epoch_LE(8))
    component epochN2b = Num2Bits(64);
    epochN2b.in <== epoch;
    signal epochBytes[8];
    for (var j = 0; j < 8; j++) {
        var lc = 0;
        for (var i = 0; i < 8; i++) { lc += epochN2b.out[j * 8 + i] * (2 ** i); }
        epochBytes[j] <== lc;
    }
    component nullH = Sha256Tagged(4, 40); // "null" + 32 secret + 8 epoch
    var nullTag[4] = [0x6e, 0x75, 0x6c, 0x6c]; // "null"
    for (var j = 0; j < 4; j++) { nullH.tag[j] <== nullTag[j]; }
    for (var j = 0; j < 32; j++) { nullH.inBytes[j] <== secret[j]; }
    for (var j = 0; j < 8; j++) { nullH.inBytes[32 + j] <== epochBytes[j]; }
    component nullOut = FieldToLeBytesFromBits();
    for (var k = 0; k < 256; k++) { nullOut.inBits[k] <== nullH.out[k]; }
    for (var j = 0; j < 32; j++) { nullifier[j] <== nullOut.bytes[j]; }

    // 4. shareX = from_le_bytes_mod_order(SHA256("shamir/x"(8)||secret||contentId))
    component shareXH = Sha256Tagged(8, 64);
    var sxTag[8] = [0x73, 0x68, 0x61, 0x6d, 0x69, 0x72, 0x2f, 0x78]; // "shamir/x"
    for (var j = 0; j < 8; j++) { shareXH.tag[j] <== sxTag[j]; }
    for (var j = 0; j < 32; j++) { shareXH.inBytes[j] <== secret[j]; }
    for (var j = 0; j < 32; j++) { shareXH.inBytes[32 + j] <== contentId[j]; }
    component shareXFr = Sha256OutToField();
    for (var k = 0; k < 256; k++) { shareXFr.out[k] <== shareXH.out[k]; }

    // 5. coeffs: coeff[0] = secret as Fr; coeff[i] = from_le(SHA256("shamir/coeff"||secret||i_LE_u32))
    signal coeff[K];
    component c0 = LeBytesToField(32);
    for (var j = 0; j < 32; j++) { c0.bytes[j] <== secret[j]; }
    coeff[0] <== c0.f;

    component coeffH[K];
    component coeffFr[K];
    var coeffTag[12] = [0x73, 0x68, 0x61, 0x6d, 0x69, 0x72, 0x2f, 0x63, 0x6f, 0x65, 0x66, 0x66]; // "shamir/coeff"
    for (var idx = 1; idx < K; idx++) {
        coeffH[idx] = Sha256Tagged(12, 36); // tag + 32 secret + 4 index
        for (var j = 0; j < 12; j++) { coeffH[idx].tag[j] <== coeffTag[j]; }
        for (var j = 0; j < 32; j++) { coeffH[idx].inBytes[j] <== secret[j]; }
        // i_LE_u32 (idx is compile-time constant): 4 LE bytes
        for (var j = 0; j < 4; j++) { coeffH[idx].inBytes[32 + j] <== (idx >> (8 * j)) & 0xff; }
        coeffFr[idx] = Sha256OutToField();
        for (var k = 0; k < 256; k++) { coeffFr[idx].out[k] <== coeffH[idx].out[k]; }
        coeff[idx] <== coeffFr[idx].f;
    }

    // 6. shareY = Horner(coeff, shareX): acc = coeff[K-1]; acc = acc*x + coeff[i]
    signal accY[K];
    accY[0] <== coeff[K - 1];
    for (var idx = 1; idx < K; idx++) {
        accY[idx] <== accY[idx - 1] * shareXFr.f + coeff[K - 1 - idx];
    }
    // output shareX, shareY as 32 LE bytes (fr_to_bytes)
    component sxBytes = FieldToLeBytes();
    sxBytes.f <== shareXFr.f;
    for (var j = 0; j < 32; j++) { shareX[j] <== sxBytes.bytes[j]; }

    component syBytes = FieldToLeBytes();
    syBytes.f <== accY[K - 1];
    for (var j = 0; j < 32; j++) { shareY[j] <== syBytes.bytes[j]; }
}

// 256 SHA output bits (MSB-first per byte) -> 32 raw LE bytes (no reduction).
template FieldToLeBytesFromBits() {
    signal input inBits[256];
    signal output bytes[32];
    for (var j = 0; j < 32; j++) {
        var lc = 0;
        for (var i = 0; i < 8; i++) { lc += inBits[j * 8 + (7 - i)] * (2 ** i); }
        bytes[j] <== lc;
    }
}

component main { public [treeRoot, epoch, contentId] } = Membership(16, 3);
