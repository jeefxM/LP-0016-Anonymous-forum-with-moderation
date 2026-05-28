//! Wire types. All 32/64-byte values are hex (no `0x`); receipts are
//! base64; `u128` stake is a decimal string. Field names are camelCase to
//! match `sdk/src/types.ts` exactly.

use base64::{engine::general_purpose::STANDARD, Engine};
use membership_registry_core::{
    ForumConfig, ForumState, Hash, MerklePath, ModeratorPubKey, ModeratorSig,
    ModerationCertificateWire, TREE_DEPTH,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;

// ── hex / base64 helpers ─────────────────────────────────────────────

pub fn enc(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn parse_hex32(s: &str, field: &str) -> Result<[u8; 32], ApiError> {
    let v = hex::decode(s).map_err(|e| ApiError::bad_request(format!("{field}: bad hex: {e}")))?;
    v.try_into()
        .map_err(|_| ApiError::bad_request(format!("{field}: expected 32 bytes")))
}

pub fn parse_hex64(s: &str, field: &str) -> Result<[u8; 64], ApiError> {
    let v = hex::decode(s).map_err(|e| ApiError::bad_request(format!("{field}: bad hex: {e}")))?;
    v.try_into()
        .map_err(|_| ApiError::bad_request(format!("{field}: expected 64 bytes")))
}

pub fn parse_merkle_path(items: &[String], field: &str) -> Result<MerklePath, ApiError> {
    if items.len() != TREE_DEPTH {
        return Err(ApiError::bad_request(format!(
            "{field}: expected {TREE_DEPTH} siblings, got {}",
            items.len()
        )));
    }
    let mut path: MerklePath = [[0u8; 32]; TREE_DEPTH];
    for (i, s) in items.iter().enumerate() {
        path[i] = parse_hex32(s, field)?;
    }
    Ok(path)
}

pub fn b64_decode(s: &str, field: &str) -> Result<Vec<u8>, ApiError> {
    STANDARD
        .decode(s)
        .map_err(|e| ApiError::bad_request(format!("{field}: bad base64: {e}")))
}

/// Derive the forum-instance PDA seed from a stable forum id. Keeps
/// `loadForumInstance(forumId)` deterministic without the daemon tracking
/// any per-forum state (ADR-004).
pub fn seed_for_forum(forum_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"forum-protocol/v1/instance-seed");
    h.update(forum_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}

// ── shared response types ────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForumInstanceDto {
    pub forum_id: String,
    pub registry_account: String,
    pub k_threshold: u8,
    pub n_threshold: u8,
    pub moderators: Vec<String>,
    pub stake_amount: String,
    pub tree_root: String,
    pub next_leaf_index: u32,
}

impl ForumInstanceDto {
    pub fn from_state(forum_id: &str, registry_account: String, s: &ForumState) -> Self {
        Self {
            forum_id: forum_id.to_string(),
            registry_account,
            k_threshold: s.config.k_threshold,
            n_threshold: s.config.n_threshold,
            moderators: s.config.moderators.iter().map(|m| enc(m)).collect(),
            stake_amount: s.config.stake_amount.to_string(),
            tree_root: enc(&s.tree_root),
            next_leaf_index: s.next_leaf_index,
        }
    }
}

// ── identity ─────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIdentityResp {
    pub secret: String,
    pub commitment: String,
}

// ── forum lifecycle ──────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateForumReq {
    pub forum_id: String,
    pub moderators: Vec<String>,
    pub n_threshold: u8,
    pub k_threshold: u8,
    /// Decimal string (u128).
    pub stake_amount: String,
}

impl CreateForumReq {
    pub fn to_config(&self) -> Result<ForumConfig, ApiError> {
        let moderators: Result<Vec<ModeratorPubKey>, _> = self
            .moderators
            .iter()
            .map(|m| parse_hex32(m, "moderators[]"))
            .collect();
        let stake_amount = self
            .stake_amount
            .parse::<u128>()
            .map_err(|e| ApiError::bad_request(format!("stakeAmount: {e}")))?;
        Ok(ForumConfig {
            k_threshold: self.k_threshold,
            n_threshold: self.n_threshold,
            moderators: moderators?,
            stake_amount,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForumIdReq {
    pub forum_id: String,
}

// ── membership ───────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterReq {
    pub forum_id: String,
    pub commitment: String,
    pub path_before: Vec<String>,
    pub leaf_index: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResp {
    pub leaf_index: u32,
    pub tx_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsRevokedReq {
    pub forum_id: String,
    pub commitment: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IsRevokedResp {
    pub revoked: bool,
}

// ── moderation certificates ──────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ModerationVoteDto {
    pub moderator: String,
    pub content_id: String,
    pub strike_index: u8,
    pub share_x: String,
    pub share_y: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignatureEntry {
    pub moderator: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ModerationCertificateDto {
    pub content_id: String,
    pub strike_index: u8,
    pub share_x: String,
    pub share_y: String,
    pub signatures: Vec<SignatureEntry>,
}

impl ModerationCertificateDto {
    pub fn from_wire(c: &ModerationCertificateWire) -> Self {
        Self {
            content_id: enc(&c.content_id),
            strike_index: c.strike_index,
            share_x: enc(&c.share_x),
            share_y: enc(&c.share_y),
            signatures: c
                .signatures
                .iter()
                .map(|(pk, sig)| SignatureEntry {
                    moderator: enc(pk),
                    signature: enc(&sig.0),
                })
                .collect(),
        }
    }

    pub fn to_wire(&self) -> Result<ModerationCertificateWire, ApiError> {
        let content_id: Hash = parse_hex32(&self.content_id, "contentId")?;
        let share_x: Hash = parse_hex32(&self.share_x, "shareX")?;
        let share_y: Hash = parse_hex32(&self.share_y, "shareY")?;
        let mut signatures = Vec::with_capacity(self.signatures.len());
        for e in &self.signatures {
            let pk: ModeratorPubKey = parse_hex32(&e.moderator, "moderator")?;
            let sig = ModeratorSig(parse_hex64(&e.signature, "signature")?);
            signatures.push((pk, sig));
        }
        Ok(ModerationCertificateWire {
            content_id,
            strike_index: self.strike_index,
            share_x,
            share_y,
            signatures,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignVoteReq {
    pub moderator_secret: String,
    pub content_id: String,
    pub strike_index: u8,
    pub share_x: String,
    pub share_y: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateReq {
    pub n_threshold: u8,
    pub votes: Vec<ModerationVoteDto>,
}

// ── slashing ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconstructReq {
    pub forum_id: String,
    pub certificates: Vec<ModerationCertificateDto>,
    pub leaf_index: u32,
    pub merkle_path: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlashEvidenceDto {
    pub commitment: String,
    pub reconstructed_secret: String,
    pub certificates: Vec<ModerationCertificateDto>,
    pub leaf_index: u32,
    pub merkle_path: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitSlashReq {
    pub forum_id: String,
    pub reconstructed_secret: String,
    pub certificates: Vec<ModerationCertificateDto>,
    pub leaf_index: u32,
    pub merkle_path: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxResp {
    pub tx_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverReq {
    pub forum_id: String,
    pub certificates: Vec<ModerationCertificateDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverResp {
    pub reconstructed_secret: String,
    pub commitment: String,
}

// ── posting / proving ────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvePostReq {
    pub secret: String,
    pub tree_root: String,
    pub merkle_siblings: Vec<String>,
    pub path_bits: u32,
    pub content_id: String,
    pub epoch: u64,
    pub k_threshold: u32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PostEnvelopeDto {
    pub content_id: String,
    pub epoch: u64,
    pub tree_root: String,
    pub nullifier: String,
    pub share_x: String,
    pub share_y: String,
    /// Groth16 proof + public signals, as `base64(JSON {proof, publicSignals})`
    /// (ADR-010).
    pub receipt: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPostReq {
    pub forum_id: String,
    pub envelope: PostEnvelopeDto,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPostResp {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
