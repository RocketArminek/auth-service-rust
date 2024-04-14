use axum::{
    routing::{get},
    Router,
};
use utoipa::OpenApi;

use crate::api::utils_controller::*;

pub fn routes() -> Router {
    Router::new()
        .route("/", get(open_api_docs_action))
        .route("/v1/health", get(health_action))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        open_api_docs_action,
        health_action,
    ),
    components(responses(HealthResponse)
))]
pub struct ApiDoc;
