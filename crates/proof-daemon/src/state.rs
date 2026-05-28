//! Shared daemon state, loaded once at boot. The daemon holds no per-forum
//! state (ADR-004): it re-derives the PDA from the forum id and re-queries
//! the chain on every call.

use std::sync::Arc;

use lez_runner::{load_program, load_state, pda_for_seed, AccountId, Program, WalletCore};
use membership_registry_core::ForumState;

use crate::dto::seed_for_forum;
use crate::error::ApiError;

pub type SharedState = Arc<AppState>;

pub struct AppState {
    /// Wallet + sequencer client. Loaded from `NSSA_WALLET_HOME_DIR` at boot
    /// (password supplied via the wallet config; see ADR-006). Dev-only for
    /// now — an `/unlock` endpoint is a P6.5/P7 follow-up.
    pub wallet: WalletCore,
    /// The compiled membership_registry program.
    pub program: Program,
    /// The post_proof guest ELF, for proving + verification.
    pub post_proof_elf: Vec<u8>,
}

impl AppState {
    /// Build from environment:
    ///   NSSA_WALLET_HOME_DIR — wallet config dir (also picked up by WalletCore)
    ///   MEMBERSHIP_REGISTRY_BIN — path to the deployed membership_registry.bin
    ///   POST_PROOF_BIN — path to the post_proof guest ELF
    pub fn from_env() -> anyhow::Result<Self> {
        let wallet = WalletCore::from_env()
            .map_err(|e| anyhow::anyhow!("WalletCore::from_env (NSSA_WALLET_HOME_DIR?): {e:?}"))?;

        let registry_bin = std::env::var("MEMBERSHIP_REGISTRY_BIN")
            .map_err(|_| anyhow::anyhow!("MEMBERSHIP_REGISTRY_BIN not set"))?;
        let program = load_program(&registry_bin)?;

        let post_proof_bin = std::env::var("POST_PROOF_BIN")
            .map_err(|_| anyhow::anyhow!("POST_PROOF_BIN not set"))?;
        let post_proof_elf =
            std::fs::read(&post_proof_bin).map_err(|e| anyhow::anyhow!("read {post_proof_bin}: {e}"))?;

        Ok(Self {
            wallet,
            program,
            post_proof_elf,
        })
    }

    /// Registry PDA for a forum id.
    pub fn pda(&self, forum_id: &str) -> AccountId {
        pda_for_seed(&self.program, seed_for_forum(forum_id))
    }

    /// Re-query the forum's on-chain state. Errors `NotFound` if the
    /// instance isn't initialised, `ChainError` if the node is unreachable.
    pub async fn forum_state(&self, forum_id: &str) -> Result<(AccountId, ForumState), ApiError> {
        let pda = self.pda(forum_id);
        let state = load_state(&self.wallet, pda)
            .await
            .map_err(ApiError::chain)?
            .ok_or_else(|| ApiError::not_found(format!("forum '{forum_id}' not found on chain")))?;
        Ok((pda, state))
    }
}
