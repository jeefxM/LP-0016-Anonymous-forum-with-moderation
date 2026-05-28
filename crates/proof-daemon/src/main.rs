//! Localhost HTTP daemon the TypeScript SDK calls (ADR-004). It wraps the
//! proven Rust crates: pure-crypto (moderation-cert, slash-evidence),
//! proving (proof-host + the post_proof guest), and chain submission
//! (lez-runner → LEZ). The member's identity secret is sent only to
//! localhost, never over the network.
//!
//! Endpoints map 1:1 to the SDK functions in `sdk/src/index.ts`. Waku-only
//! operations (publishCertificate, listCertificatesForMember) are NOT here —
//! they live in the TS transport layer (P6.4).
//!
//! Build + run on Hetzner (needs the LEZ checkout + the prover + ELFs):
//!   NSSA_WALLET_HOME_DIR=~/lez/wallet/configs/debug \
//!   MEMBERSHIP_REGISTRY_BIN=~/.../membership_registry.bin \
//!   POST_PROOF_BIN=~/.../post_proof.bin \
//!   RISC0_DEV_MODE=0 cargo run --release

mod chain;
mod crypto;
mod dto;
mod error;
mod proving;
mod state;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Json, Router,
};

use state::{AppState, SharedState};

/// Real-mode RISC0 receipts are hundreds of KB to a few MB, and they ride
/// in the `/v1/post/verify` request body. Raise axum's 2 MB default so the
/// SDK can round-trip a real envelope.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let state: SharedState = std::sync::Arc::new(AppState::from_env()?);

    let app = Router::new()
        .route("/v1/health", get(health))
        // pure crypto
        .route("/v1/identity/create", post(crypto::create_identity))
        .route("/v1/moderation/sign", post(crypto::sign_vote))
        .route("/v1/moderation/aggregate", post(crypto::aggregate))
        // chain
        .route("/v1/forum/create", post(chain::create_forum))
        .route("/v1/forum/load", post(chain::load_forum))
        .route("/v1/member/register", post(chain::register))
        .route("/v1/member/is-revoked", post(chain::is_revoked))
        .route("/v1/slash/reconstruct", post(chain::reconstruct))
        .route("/v1/slash/recover", post(chain::recover))
        .route("/v1/slash/submit", post(chain::submit_slash))
        // proving
        .route("/v1/post/prove", post(proving::prove_post))
        .route("/v1/post/verify", post(proving::verify_post))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let addr = std::env::var("DAEMON_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("proof-daemon listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
