use axum::http::StatusCode;
use axum::Json;
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

#[utoipa::path(get, path = "/",
    responses(
        (status = 200, description = "Open api schema", content_type = "application/json"),
    )
)]
pub async fn open_api_docs_action() {}

#[derive(Serialize, Deserialize, ToResponse, ToSchema)]
pub struct HealthResponse {
    pub message: String,
}
