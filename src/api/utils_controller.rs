use axum::http::StatusCode;
use axum::{Json};
use crate::api::dto::HealthResponse;

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
