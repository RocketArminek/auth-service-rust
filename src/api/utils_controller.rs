use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToResponse};
use crate::api::routes::ApiDoc;

#[utoipa::path(get, path = "/v1/health",
    responses(
        (status = 200, description = "Health check action", content_type = "application/json", body = HealthResponse),
    )
)]
pub async fn health_action() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { message: String::from("OK") }))
}

#[utoipa::path(get, path = "/",
    responses(
        (status = 200, description = "Open api schema", content_type = "application/json"),
    )
)]
pub async fn open_api_docs_action() -> (StatusCode, String) {
    match ApiDoc::openapi().to_json() {
        Ok(response) => {
            (StatusCode::OK, response)
        }
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, String::from("Internal Server Error"))
        }
    }
}

#[derive(Serialize, Deserialize, ToResponse)]
pub struct HealthResponse {
    pub message: String,
}
