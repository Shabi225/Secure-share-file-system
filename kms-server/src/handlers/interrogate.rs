use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::crypto::chacha::wrap_dek;
use crate::db::vault::retrieve_key;

#[derive(Serialize)]
pub struct InterrogationResponse {
    pub ephemeral_key_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn handle_interrogation(
    State(pool): State<PgPool>,
    Path(file_id): Path<Uuid>,
) -> impl IntoResponse {
    let dek_blob = match retrieve_key(&pool, file_id).await {
        Ok(Some(blob)) => blob,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "File not found".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse { error: e }),
            )
                .into_response();
        }
    };

    let wrapped_payload = match wrap_dek(&dek_blob) {
        Ok(payload) => payload,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
                .into_response();
        }
    };

    let response = InterrogationResponse {
        ephemeral_key_b64: BASE64.encode(wrapped_payload.ephemeral_key),
        nonce_b64: BASE64.encode(wrapped_payload.nonce),
        ciphertext_b64: BASE64.encode(wrapped_payload.ciphertext),
    };

    (StatusCode::OK, Json(response)).into_response()
}
