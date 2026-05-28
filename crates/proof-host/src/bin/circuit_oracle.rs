//! Prints the Rust `prove_post` journal for fixed inputs, as the oracle the
//! Groth16 circuit (circuits/membership.circom) must reproduce byte-for-byte
//! (ADR-010). Run: cargo run -p proof-host --bin circuit_oracle

use post_proof_core::{build_singleton_tree, prove_post, PrivateInputs, PublicInputs};

fn main() {
    // Canonical Fr secret (first 16 bytes set → well under r).
    let mut secret = [0u8; 32];
    secret[0..16].copy_from_slice(&[0xA5u8; 16]);

    let (root, siblings) = build_singleton_tree(&secret);
    let private = PrivateInputs {
        secret,
        merkle_siblings: siblings,
        merkle_path_bits: 0,
    };
    let public = PublicInputs {
        tree_root: root,
        epoch: 1,
        content_id: [42u8; 32],
        k_threshold: 3,
    };
    let j = prove_post(&private, &public).expect("prove");

    println!("secret={}", hex::encode(secret));
    for (i, s) in siblings.iter().enumerate() {
        println!("sib{}={}", i, hex::encode(s));
    }
    println!("treeRoot={}", hex::encode(j.tree_root));
    println!("epoch={}", j.epoch);
    println!("contentId={}", hex::encode(j.content_id));
    println!("nullifier={}", hex::encode(j.nullifier));
    println!("shareX={}", hex::encode(j.share_x));
    println!("shareY={}", hex::encode(j.share_y));
}
