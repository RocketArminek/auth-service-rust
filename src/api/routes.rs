use axum::routing::post;
use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

use crate::api::user_controller::*;
use crate::api::utils_controller::*;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;

pub fn routes(repository: MysqlUserRepository) -> Router {
    Router::new()
        .route("/", get(open_api_docs_action))
        .route("/v1/health", get(health_action))
        .route("/v1/users", post(create_user))
        .layer(TraceLayer::new_for_http())
        .with_state(repository)
}

#[derive(OpenApi)]
#[openapi(
    servers(
        (description="dev", url="http://localhost:8080"),
        (description="production", url="https://auth-api-rust.arminek.xyz"),
    ),
    paths(
        open_api_docs_action,
        health_action,
        create_user,
    ),
    components(
        responses(HealthResponse),
        schemas(CreateUserRequest),
    )
)]
pub struct ApiDoc;
