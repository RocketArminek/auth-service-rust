use axum::routing::post;
use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use crate::api::ServerState;

use crate::api::user_controller::*;
use crate::api::utils_controller::*;
use crate::domain::crypto::HashingScheme;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;

pub fn routes(secret: String, hashing_scheme: HashingScheme, repository: MysqlUserRepository) -> Router {
    Router::new()
        .route("/", get(open_api_docs_action))
        .route("/v1/health", get(health_action))
        .route("/v1/users", post(create_user))
        .route("/v1/users/login", post(login))
        .layer(TraceLayer::new_for_http())
        .with_state(ServerState{secret, hashing_scheme, repository})
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
        login,
    ),
    components(
        responses(HealthResponse, LoginResponse, SessionResponse, ErrorResponse),
        schemas(CreateUserRequest, LoginRequest),
    )
)]
pub struct ApiDoc;
