use axum::http::StatusCode;
use axum::{Json};
use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

#[utoipa::path(get, path = "/v1/health",
    responses(
        (status = 200, description = "Health check action", content_type = "application/json", body = HealthResponse),
    )
)]
pub async fn health_action() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            message: String::from("OK"),
        }),
    )
}

#[derive(Serialize, Deserialize, ToResponse, ToSchema)]
pub struct HealthResponse {
    pub message: String,
}
