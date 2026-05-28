pragma circom 2.1.6;

// PERF-2 pre-flight: confirm circomlib SHA-256 over the exact node-hash
// preimage ("node" ‖ left ‖ right = 68 bytes = 544 bits) is bit-identical
// to standard SHA-256 (Rust sha2). Input bits are MSB-first per byte.
include "circomlib/circuits/sha256/sha256.circom";

template NodeHash() {
    signal input in[544];
    signal output out[256];
    component h = Sha256(544);
    for (var i = 0; i < 544; i++) { h.in[i] <== in[i]; }
    for (var i = 0; i < 256; i++) { out[i] <== h.out[i]; }
}

component main = NodeHash();
