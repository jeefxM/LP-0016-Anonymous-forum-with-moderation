//! Pure-crypto handlers — no chain, no proving. These wrap `moderation-cert`
//! and the identity/share helpers. They build on the Mac.

use axum::Json;
use ed25519_dalek::SigningKey;
use membership_registry_core::ModeratorSig;
use post_proof_core::shamir;
use rand::{rngs::OsRng, RngCore};
use slash_evidence::commitment_of;

use crate::dto::{
    enc, parse_hex32, parse_hex64, AggregateReq, CreateIdentityResp, ModerationCertificateDto,
    ModerationVoteDto, SignVoteReq,
};
use crate::error::{ApiError, ApiResult, ErrorKind};

/// Generate a fresh member identity. The secret is canonicalised to a BN254
/// `Fr` so `secret → Fr → bytes` round-trips — required for the commitment
/// to match during slash reconstruction.
pub async fn create_identity() -> ApiResult<Json<CreateIdentityResp>> {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let fr = shamir::secret_to_fr(&raw);
    let secret = shamir::fr_to_bytes(&fr);
    let commitment = commitment_of(&secret);
    Ok(Json(CreateIdentityResp {
        secret: enc(&secret),
        commitment: enc(&commitment),
    }))
}

/// One moderator signs one strike over a post's bound Shamir share.
pub async fn sign_vote(Json(req): Json<SignVoteReq>) -> ApiResult<Json<ModerationVoteDto>> {
    let sk_bytes = parse_hex32(&req.moderator_secret, "moderatorSecret")?;
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let content_id = parse_hex32(&req.content_id, "contentId")?;
    let share_x = parse_hex32(&req.share_x, "shareX")?;
    let share_y = parse_hex32(&req.share_y, "shareY")?;

    let vote = moderation_cert::sign_vote(&signing_key, content_id, req.strike_index, share_x, share_y);
    Ok(Json(ModerationVoteDto {
        moderator: enc(&vote.moderator_pub),
        content_id: enc(&vote.content_id),
        strike_index: vote.strike_index,
        share_x: enc(&vote.share_x),
        share_y: enc(&vote.share_y),
        signature: enc(&vote.signature.0),
    }))
}

/// Aggregate ≥ N independent votes into one certificate.
pub async fn aggregate(Json(req): Json<AggregateReq>) -> ApiResult<Json<ModerationCertificateDto>> {
    let mut votes = Vec::with_capacity(req.votes.len());
    for v in &req.votes {
        votes.push(moderation_cert::Vote {
            moderator_pub: parse_hex32(&v.moderator, "moderator")?,
            content_id: parse_hex32(&v.content_id, "contentId")?,
            strike_index: v.strike_index,
            share_x: parse_hex32(&v.share_x, "shareX")?,
            share_y: parse_hex32(&v.share_y, "shareY")?,
            signature: ModeratorSig(parse_hex64(&v.signature, "signature")?),
        });
    }
    let cert = moderation_cert::aggregate(&votes, req.n_threshold).map_err(|e| match e {
        moderation_cert::CertError::BelowThreshold { .. } => {
            ApiError::new(ErrorKind::BelowThreshold, e.to_string())
        }
        other => ApiError::bad_request(other.to_string()),
    })?;
    Ok(Json(ModerationCertificateDto::from_wire(&cert)))
}
