use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

pub async fn health_action() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { message: String::from("OK") }))
}

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub message: String,
}
