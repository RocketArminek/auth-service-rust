use crate::api::acl_mw::{restricted_acl, verified_acl};
use axum::routing::{patch, post, put};
use axum::{middleware, routing::get, Router};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::api::dto::*;
use crate::api::restricted_controller::*;
use crate::api::server_state::ServerState;
use crate::api::stateless_auth_controller::*;
use crate::api::user_controller::*;
use crate::api::utils_controller::*;
use crate::domain::jwt::UserDTO;

pub fn routes(state: ServerState) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/", ApiDoc::openapi()))
        .route("/v1/health", get(health_action))
        .route("/v1/users", post(create_user))
        .route("/v1/me/verification", patch(verify))
        .route("/v1/me/verification/resend", post(resend_verification))
        .route("/v1/me/password/reset", patch(reset_password))
        .route("/v1/stateless/login", post(login))
        .route("/v1/stateless/refresh", post(refresh))
        .route("/v1/password/reset", post(request_password_reset))
        .merge(
            Router::new()
                .route("/v1/me", put(update_profile))
                .route("/v1/stateless/authenticate", get(authenticate))
                .layer(
                    ServiceBuilder::new()
                        .layer(middleware::from_fn_with_state(state.clone(), verified_acl))
                        .layer(TraceLayer::new_for_http()),
                ),
        )
        .merge(
            Router::new()
                .route(
                    "/v1/restricted/users",
                    post(create_restricted_user).get(get_all_users),
                )
                .route(
                    "/v1/restricted/users/{id}",
                    get(get_user).delete(delete_user).put(update_user),
                )
                .layer(
                    ServiceBuilder::new()
                        .layer(middleware::from_fn_with_state(
                            state.clone(),
                            restricted_acl,
                        ))
                        .layer(TraceLayer::new_for_http()),
                ),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(OpenApi)]
#[openapi(
    servers(
        (description="dev", url="http://localhost:8080"),
    ),
    paths(
        open_api_docs,
        health_action,
        create_user,
        create_restricted_user,
        get_all_users,
        get_user,
        delete_user,
        login,
        authenticate,
        refresh,
        update_profile,
        update_user,
        verify,
        resend_verification,
        request_password_reset,
        reset_password,
    ),
    components(
        schemas(
            HealthResponse,
            MessageResponse,
            UserDTO,
            LoginResponse,
            TokenResponse,
            CreateUserRequest,
            UpdateUserRequest,
            LoginRequest,
            CreatedResponse,
            UserListResponse,
            VerifyUserRequest,
            ResetPasswordRequest,
            ChangePasswordRequest,
        ),
    )
)]
pub struct ApiDoc;

#[utoipa::path(get, path = "/",
    tag="utils",
    responses(
        (status = 200, description = "Open api schema", content_type = "application/json"),
    )
)]
pub async fn open_api_docs() {
    panic!("This is only for documentation")
}
