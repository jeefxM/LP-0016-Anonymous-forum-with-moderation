//! Proving handlers — generate and verify post-proofs. These call the
//! RISC0 prover (proof-host) and only run on a host with the prover +
//! guest ELF (Hetzner). Proving blocks for tens of seconds (ADR-002), so
//! it runs on a blocking thread; the SDK must use a generous fetch timeout.

use axum::{extract::State, Json};
use post_proof_core::{PrivateInputs, PublicInputs};
use proof_host::{prove_post as host_prove, receipt_from_bytes, receipt_to_bytes, verify_post as host_verify};

use crate::dto::{
    b64_decode, b64_encode, enc, parse_hex32, parse_merkle_path, PostEnvelopeDto, ProvePostReq,
    VerifyPostReq, VerifyPostResp,
};
use crate::error::{ApiError, ApiResult, ErrorKind};
use crate::state::SharedState;

/// Produce a `PostEnvelope`: a ZK proof of non-revoked membership plus the
/// post-bound Shamir share. The caller supplies the Merkle siblings + path
/// bits (ADR-004 — the daemon doesn't track the tree).
pub async fn prove_post(
    State(state): State<SharedState>,
    Json(req): Json<ProvePostReq>,
) -> ApiResult<Json<PostEnvelopeDto>> {
    let secret = parse_hex32(&req.secret, "secret")?;
    let tree_root = parse_hex32(&req.tree_root, "treeRoot")?;
    let content_id = parse_hex32(&req.content_id, "contentId")?;
    let merkle_siblings = parse_merkle_path(&req.merkle_siblings, "merkleSiblings")?;

    let private = PrivateInputs {
        secret,
        merkle_siblings,
        merkle_path_bits: req.path_bits,
    };
    let public = PublicInputs {
        tree_root,
        epoch: req.epoch,
        content_id,
        k_threshold: req.k_threshold,
    };

    let elf = state.post_proof_elf.clone();
    let (receipt, journal) = tokio::task::spawn_blocking(move || host_prove(&elf, &private, &public))
        .await
        .map_err(|e| ApiError::proof(format!("prover task join: {e}")))?
        .map_err(ApiError::proof)?;

    let receipt_bytes = receipt_to_bytes(&receipt).map_err(ApiError::proof)?;
    Ok(Json(PostEnvelopeDto {
        content_id: enc(&journal.content_id),
        epoch: journal.epoch,
        tree_root: enc(&journal.tree_root),
        nullifier: enc(&journal.nullifier),
        share_x: enc(&journal.share_x),
        share_y: enc(&journal.share_y),
        receipt: b64_encode(&receipt_bytes),
    }))
}

/// Verify a `PostEnvelope`: the receipt must verify, its committed root
/// must match the envelope, and that root must be the current on-chain
/// root (stale roots are rejected).
///
/// Note: a post envelope is anonymous — it carries a nullifier and shares,
/// not the member's commitment — so revocation cannot be checked here.
/// Revocation is enforced via root rotation / a future non-membership
/// proof (see docs/protocol.md and ADR-004 consequences).
pub async fn verify_post(
    State(state): State<SharedState>,
    Json(req): Json<VerifyPostReq>,
) -> ApiResult<Json<VerifyPostResp>> {
    let receipt_bytes = b64_decode(&req.envelope.receipt, "receipt")?;
    let receipt = receipt_from_bytes(&receipt_bytes)
        .map_err(|e| ApiError::new(ErrorKind::InvalidProof, e.to_string()))?;

    let elf = state.post_proof_elf.clone();
    let journal = match tokio::task::spawn_blocking(move || host_verify(&elf, &receipt))
        .await
        .map_err(|e| ApiError::proof(format!("verify task join: {e}")))?
    {
        Ok(j) => j,
        Err(e) => {
            return Ok(Json(VerifyPostResp {
                valid: false,
                reason: Some(e.to_string()),
            }))
        }
    };

    let claimed_root = parse_hex32(&req.envelope.tree_root, "envelope.treeRoot")?;
    if journal.tree_root != claimed_root {
        return Ok(Json(VerifyPostResp {
            valid: false,
            reason: Some("envelope tree_root does not match the proof".into()),
        }));
    }

    let (_pda, s) = state.forum_state(&req.forum_id).await?;
    if journal.tree_root != s.tree_root {
        return Ok(Json(VerifyPostResp {
            valid: false,
            reason: Some("proof targets a stale tree_root".into()),
        }));
    }

    Ok(Json(VerifyPostResp {
        valid: true,
        reason: None,
    }))
}
