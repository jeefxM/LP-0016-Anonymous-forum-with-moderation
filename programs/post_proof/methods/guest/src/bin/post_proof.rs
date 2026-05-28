//! Post-proof RISC0 guest (P3 optimised v2).
//!
//! Reads inputs as a single contiguous u8 slice via `env::read_slice` and
//! passes byte slices straight to `prove_post_from_bytes`. No struct
//! materialisation, no double pass, no serde — that's the path that
//! brought us under budget (see ADR-002).

#![no_main]

use post_proof_core::{
    prove_post_from_bytes, PRIVATE_INPUTS_BYTES, PUBLIC_INPUTS_BYTES,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut priv_bytes = [0u8; PRIVATE_INPUTS_BYTES];
    env::read_slice(&mut priv_bytes);

    let mut pub_bytes = [0u8; PUBLIC_INPUTS_BYTES];
    env::read_slice(&mut pub_bytes);

    let journal = prove_post_from_bytes(&priv_bytes, &pub_bytes)
        .unwrap_or_else(|e| panic!("{e}"));
    env::commit(&journal);
}
