use crate::api::ServerState;
use axum::routing::{any, post};
use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

use crate::api::user_controller::*;
use crate::api::utils_controller::*;
use crate::domain::crypto::HashingScheme;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;

pub fn routes(
    secret: String,
    hashing_scheme: HashingScheme,
    repository: MysqlUserRepository,
) -> Router {
    Router::new()
        .route("/", get(open_api_docs_action))
        .route("/v1/health", get(health_action))
        .route("/v1/users", post(create_user))
        .route("/v1/users/login", post(login))
        .route("/v1/users/verify", any(verify))
        .layer(TraceLayer::new_for_http())
        .with_state(ServerState {
            secret,
            hashing_scheme,
            repository,
        })
}

#[derive(OpenApi)]
#[openapi(
    servers(
        (description="dev", url="http://localhost:8080"),
        (description="4e-production", url="https://auth-4ecommerce.arminek.xyz"),
    ),
    paths(
        open_api_docs_action,
        health_action,
        create_user,
        login,
        verify,
    ),
    components(
        responses(HealthResponse, AuthResponse, SessionResponse, MessageResponse),
        schemas(HealthResponse, AuthResponse, SessionResponse, MessageResponse, CreateUserRequest, LoginRequest),
    )
)]
pub struct ApiDoc;
