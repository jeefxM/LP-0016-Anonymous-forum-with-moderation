//! Aggregates ≥K moderation certificates for a single commitment and
//! reconstructs the member's nullifier secret via Shamir recovery, ready to
//! be submitted as the slash transaction's instruction payload.
//!
//! Real implementation lands in P5.
