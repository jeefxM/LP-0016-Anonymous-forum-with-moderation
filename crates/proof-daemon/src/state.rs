//! Shared daemon state, loaded once at boot. The daemon holds no per-forum
//! state (ADR-004): it re-derives the PDA from the forum id and re-queries
//! the chain on every call.

use std::path::PathBuf;
use std::sync::Arc;

use lez_runner::{load_program, load_state, pda_for_seed, AccountId, Program, WalletCore};
use membership_registry_core::ForumState;

use crate::dto::seed_for_forum;
use crate::error::ApiError;

pub type SharedState = Arc<AppState>;

/// Paths + parameters for the Groth16 membership circuit (ADR-010). The
/// daemon shells out to `node` (witness generation), the rapidsnark `prover`
/// (Groth16 proving), and `snarkjs` (Groth16 verification). All circuit
/// artifacts live under `dir`.
pub struct CircuitConfig {
    /// Directory holding `membership_js/`, `membership_0.zkey`, `vkey.json`.
    pub dir: PathBuf,
    /// rapidsnark `prover` binary.
    pub prover_bin: PathBuf,
    /// `node` launcher (witness generation via the circom-emitted wasm).
    pub node_bin: String,
    /// `snarkjs` launcher (Groth16 verification).
    pub snarkjs_bin: String,
    /// Compile-time threshold `K` the circuit was built for. One zkey per `K`
    /// (ADR-010); requests with a different `kThreshold` are rejected.
    pub k: u32,
}

impl CircuitConfig {
    pub fn wasm(&self) -> PathBuf {
        self.dir.join("membership_js").join("membership.wasm")
    }
    pub fn witness_gen(&self) -> PathBuf {
        self.dir.join("membership_js").join("generate_witness.js")
    }
    pub fn zkey(&self) -> PathBuf {
        self.dir.join("membership_0.zkey")
    }
    pub fn vkey(&self) -> PathBuf {
        self.dir.join("vkey.json")
    }
}

pub struct AppState {
    /// Wallet + sequencer client. Loaded from `NSSA_WALLET_HOME_DIR` at boot
    /// (password supplied via the wallet config; see ADR-006). Dev-only for
    /// now — an `/unlock` endpoint is a P6.5/P7 follow-up.
    pub wallet: WalletCore,
    /// The compiled membership_registry program.
    pub program: Program,
    /// Groth16 membership-circuit artifacts + tools (ADR-010).
    pub circuit: CircuitConfig,
}

impl AppState {
    /// Build from environment:
    ///   NSSA_WALLET_HOME_DIR — wallet config dir (also picked up by WalletCore)
    ///   MEMBERSHIP_REGISTRY_BIN — path to the deployed membership_registry.bin
    ///   CIRCUIT_DIR — dir with membership_js/, membership_0.zkey, vkey.json
    ///   RAPIDSNARK_PROVER — path to the rapidsnark `prover` binary
    ///   CIRCUIT_K — threshold the circuit was compiled for (default 3)
    ///   NODE_BIN / SNARKJS_BIN — launchers (default "node" / "snarkjs")
    pub fn from_env() -> anyhow::Result<Self> {
        let wallet = WalletCore::from_env()
            .map_err(|e| anyhow::anyhow!("WalletCore::from_env (NSSA_WALLET_HOME_DIR?): {e:?}"))?;

        let registry_bin = std::env::var("MEMBERSHIP_REGISTRY_BIN")
            .map_err(|_| anyhow::anyhow!("MEMBERSHIP_REGISTRY_BIN not set"))?;
        let program = load_program(&registry_bin)?;

        let dir: PathBuf = std::env::var("CIRCUIT_DIR")
            .map_err(|_| anyhow::anyhow!("CIRCUIT_DIR not set"))?
            .into();
        let prover_bin: PathBuf = std::env::var("RAPIDSNARK_PROVER")
            .map_err(|_| anyhow::anyhow!("RAPIDSNARK_PROVER not set"))?
            .into();
        let node_bin = std::env::var("NODE_BIN").unwrap_or_else(|_| "node".to_string());
        let snarkjs_bin = std::env::var("SNARKJS_BIN").unwrap_or_else(|_| "snarkjs".to_string());
        let k = std::env::var("CIRCUIT_K")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);

        let circuit = CircuitConfig {
            dir,
            prover_bin,
            node_bin,
            snarkjs_bin,
            k,
        };
        for p in [
            circuit.wasm(),
            circuit.witness_gen(),
            circuit.zkey(),
            circuit.vkey(),
            circuit.prover_bin.clone(),
        ] {
            if !p.exists() {
                anyhow::bail!("circuit artifact missing: {}", p.display());
            }
        }

        Ok(Self {
            wallet,
            program,
            circuit,
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
