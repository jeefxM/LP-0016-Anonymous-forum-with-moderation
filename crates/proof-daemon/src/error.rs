//! API error type. Serialises to `{ "kind", "message" }`, mirroring the
//! SDK's `ForumError` (sdk/src/types.ts) so the client can map `kind` back
//! onto a typed `ForumErrorKind`.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    BadRequest,
    ProofFailed,
    InvalidProof,
    Revoked,
    BelowThreshold,
    ChainError,
    NotFound,
}

#[derive(Debug)]
pub struct ApiError {
    pub kind: ErrorKind,
    pub message: String,
}

impl ApiError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::BadRequest, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }
    pub fn chain(e: impl std::fmt::Display) -> Self {
        Self::new(ErrorKind::ChainError, e.to_string())
    }
    pub fn proof(e: impl std::fmt::Display) -> Self {
        Self::new(ErrorKind::ProofFailed, e.to_string())
    }
}

#[derive(Serialize)]
struct ErrBody {
    kind: ErrorKind,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.kind {
            ErrorKind::BadRequest => StatusCode::BAD_REQUEST,
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::Revoked => StatusCode::FORBIDDEN,
            ErrorKind::BelowThreshold | ErrorKind::InvalidProof => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorKind::ChainError => StatusCode::BAD_GATEWAY,
            ErrorKind::ProofFailed => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrBody {
                kind: self.kind,
                message: self.message,
            }),
        )
            .into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
