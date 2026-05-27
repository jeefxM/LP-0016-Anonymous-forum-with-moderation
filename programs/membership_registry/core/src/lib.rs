//! Shared types for the `membership_registry` LEZ program.
//!
//! This crate is intentionally minimal during P0. Real `Instruction` and
//! state types land in P2 once the LEZ program plumbing is wired up.

#![cfg_attr(not(feature = "std"), no_std)]

pub const PROGRAM_NAME: &str = "forum-protocol/membership-registry";
