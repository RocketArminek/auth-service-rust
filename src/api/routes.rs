use crate::api::ServerState;
use axum::routing::{any, post};
use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::api::user_controller::*;
use crate::api::utils_controller::*;

pub fn routes(
    state: ServerState
) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/", ApiDoc::openapi()))
        .route("/v1/health", get(health_action))
        .route("/v1/users", post(create_user))
        .route("/v1/users/login", post(login))
        .route("/v1/users/verify", any(verify))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(OpenApi)]
#[openapi(
    servers(
        (description="dev", url="http://localhost:8080"),
        (description="4e-production", url="https://auth-4ecommerce.arminek.xyz"),
    ),
    paths(
        open_api_docs,
        health_action,
        create_user,
        login,
        verify,
    ),
    components(
        responses(HealthResponse, SessionResponse, MessageResponse),
        schemas(HealthResponse, SessionResponse, MessageResponse, CreateUserRequest, LoginRequest),
    )
)]
pub struct ApiDoc;

#[utoipa::path(get, path = "/",
    responses(
        (status = 200, description = "Open api schema", content_type = "application/json"),
    )
)]
pub async fn open_api_docs() { panic!("This is only for documentation") }
