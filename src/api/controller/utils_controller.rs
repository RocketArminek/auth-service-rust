use crate::api::dto::HealthResponse;
use axum::Json;
use axum::http::StatusCode;

#[utoipa::path(get, path = "/v1/health",
    tag="utils",
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
