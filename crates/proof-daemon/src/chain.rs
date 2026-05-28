//! Chain handlers — initialise/load forums, register members, query
//! revocation, reconstruct slash evidence, and submit slashes. All go
//! through the `lez_runner` library. The daemon holds no tree state: the
//! caller supplies Merkle paths, and we re-query the PDA per call (ADR-004).

use axum::{extract::State, Json};
use lez_runner::{initialize, poll_until, register as chain_register, slash};
use slash_evidence::{build_slash_payload, commitment_of, recover_commitment, SlashError};

use crate::dto::{
    enc, parse_hex32, parse_merkle_path, seed_for_forum, CreateForumReq, ForumIdReq,
    ForumInstanceDto, IsRevokedReq, IsRevokedResp, ModerationCertificateDto, RecoverReq,
    RecoverResp, ReconstructReq, RegisterReq, RegisterResp, SlashEvidenceDto, SubmitSlashReq,
    TxResp,
};
use crate::error::{ApiError, ApiResult, ErrorKind};
use crate::state::SharedState;

const MAX_POLL: u32 = 25;

/// `Initialize` a forum instance and return its on-chain state. Idempotent
/// from the caller's view: if the instance already exists, the on-chain
/// program rejects the re-init and we return the current state.
pub async fn create_forum(
    State(state): State<SharedState>,
    Json(req): Json<CreateForumReq>,
) -> ApiResult<Json<ForumInstanceDto>> {
    let config = req.to_config()?;
    let seed = seed_for_forum(&req.forum_id);
    let (pda, _tx) = initialize(&state.wallet, &state.program, seed, config)
        .await
        .map_err(ApiError::chain)?;
    let s = poll_until(&state.wallet, pda, "Initialize", MAX_POLL, |_| true)
        .await
        .map_err(ApiError::chain)?;
    Ok(Json(ForumInstanceDto::from_state(
        &req.forum_id,
        pda.to_string(),
        &s,
    )))
}

/// Load an existing instance's current state.
pub async fn load_forum(
    State(state): State<SharedState>,
    Json(req): Json<ForumIdReq>,
) -> ApiResult<Json<ForumInstanceDto>> {
    let (pda, s) = state.forum_state(&req.forum_id).await?;
    Ok(Json(ForumInstanceDto::from_state(
        &req.forum_id,
        pda.to_string(),
        &s,
    )))
}

/// Register a member commitment at `leaf_index` with the caller-supplied
/// `path_before`. Polls until the leaf count advances.
pub async fn register(
    State(state): State<SharedState>,
    Json(req): Json<RegisterReq>,
) -> ApiResult<Json<RegisterResp>> {
    let pda = state.pda(&req.forum_id);
    let commitment = parse_hex32(&req.commitment, "commitment")?;
    let path_before = parse_merkle_path(&req.path_before, "pathBefore")?;
    let tx = chain_register(
        &state.wallet,
        &state.program,
        pda,
        commitment,
        path_before,
        req.leaf_index,
    )
    .await
    .map_err(ApiError::chain)?;

    let target = req.leaf_index + 1;
    poll_until(&state.wallet, pda, "Register", MAX_POLL, move |st| {
        st.next_leaf_index >= target
    })
    .await
    .map_err(ApiError::chain)?;

    Ok(Json(RegisterResp {
        leaf_index: req.leaf_index,
        tx_hash: tx,
    }))
}

/// True if a commitment is in the instance's on-chain revocation set.
pub async fn is_revoked(
    State(state): State<SharedState>,
    Json(req): Json<IsRevokedReq>,
) -> ApiResult<Json<IsRevokedResp>> {
    let (_pda, s) = state.forum_state(&req.forum_id).await?;
    let commitment = parse_hex32(&req.commitment, "commitment")?;
    Ok(Json(IsRevokedResp {
        revoked: s.revocation_set.contains(&commitment),
    }))
}

/// Try to assemble slash evidence from accumulated certs. Returns `null`
/// (HTTP 200) when fewer than K certs are present; errors otherwise.
pub async fn reconstruct(
    State(state): State<SharedState>,
    Json(req): Json<ReconstructReq>,
) -> ApiResult<Json<Option<SlashEvidenceDto>>> {
    let (_pda, s) = state.forum_state(&req.forum_id).await?;
    let mut certs = Vec::with_capacity(req.certificates.len());
    for c in &req.certificates {
        certs.push(c.to_wire()?);
    }
    let merkle_path = parse_merkle_path(&req.merkle_path, "merklePath")?;

    match build_slash_payload(
        &certs,
        &s.config.moderators,
        s.config.n_threshold,
        s.config.k_threshold,
        s.tree_root,
        req.leaf_index,
        merkle_path,
        &s.revocation_set,
    ) {
        Ok(payload) => Ok(Json(Some(SlashEvidenceDto {
            commitment: enc(&payload.commitment),
            reconstructed_secret: enc(&payload.reconstructed_secret),
            certificates: payload
                .certificates
                .iter()
                .map(ModerationCertificateDto::from_wire)
                .collect(),
            leaf_index: payload.leaf_index,
            merkle_path: payload.merkle_path.iter().map(|h| enc(h)).collect(),
        }))),
        // Not enough evidence yet — not an error, just "can't slash yet".
        Err(SlashError::BelowKThreshold { .. }) => Ok(Json(None)),
        Err(SlashError::AlreadyRevoked) => {
            Err(ApiError::new(ErrorKind::Revoked, "member already revoked"))
        }
        Err(e) => Err(ApiError::bad_request(e.to_string())),
    }
}

/// Recover the member's secret + commitment from ≥K certs (no Merkle check).
/// Lets the slasher learn the commitment — and thus the member's leaf — before
/// assembling full slash evidence (ADR-009). Returns `null` below K.
pub async fn recover(
    State(state): State<SharedState>,
    Json(req): Json<RecoverReq>,
) -> ApiResult<Json<Option<RecoverResp>>> {
    let (_pda, s) = state.forum_state(&req.forum_id).await?;
    let mut certs = Vec::with_capacity(req.certificates.len());
    for c in &req.certificates {
        certs.push(c.to_wire()?);
    }
    match recover_commitment(&certs, &s.config.moderators, s.config.n_threshold, s.config.k_threshold) {
        Ok((secret, commitment)) => Ok(Json(Some(RecoverResp {
            reconstructed_secret: enc(&secret),
            commitment: enc(&commitment),
        }))),
        Err(SlashError::BelowKThreshold { .. }) => Ok(Json(None)),
        Err(e) => Err(ApiError::bad_request(e.to_string())),
    }
}

/// Submit a slash. The on-chain verifier re-checks everything (ADR-008).
/// Polls until the member's commitment appears in the revocation set.
pub async fn submit_slash(
    State(state): State<SharedState>,
    Json(req): Json<SubmitSlashReq>,
) -> ApiResult<Json<TxResp>> {
    let pda = state.pda(&req.forum_id);
    let reconstructed_secret = parse_hex32(&req.reconstructed_secret, "reconstructedSecret")?;
    let merkle_path = parse_merkle_path(&req.merkle_path, "merklePath")?;
    let mut certs = Vec::with_capacity(req.certificates.len());
    for c in &req.certificates {
        certs.push(c.to_wire()?);
    }

    let tx = slash(
        &state.wallet,
        &state.program,
        pda,
        reconstructed_secret,
        certs,
        req.leaf_index,
        merkle_path,
    )
    .await
    .map_err(ApiError::chain)?;

    let commitment = commitment_of(&reconstructed_secret);
    poll_until(&state.wallet, pda, "Slash", MAX_POLL, move |st| {
        st.revocation_set.contains(&commitment)
    })
    .await
    .map_err(ApiError::chain)?;

    Ok(Json(TxResp { tx_hash: tx }))
}
