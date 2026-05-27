//! Host-side prover wrapper for the post-proof RISC0 guest.
//!
//! Real implementation lands in P1 (`P1.4`). For now this crate exists to
//! keep the workspace topology stable.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
