use crate::api::dto::{LoginRequest, LoginResponse, MessageResponse};
use crate::api::extractor::auth_extractor::BearerToken;
use crate::api::response::auth_response::IntoAuthResponse;
use crate::api::server_state::ServerState;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;

#[utoipa::path(post, path = "/v1/login",
    tag="auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login response", content_type = "application/json", body = LoginResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn login(
    State(state): State<ServerState>,
    request: Json<LoginRequest>,
) -> impl IntoResponse {
    state
        .auth_service
        .login(request.email.clone(), request.password.clone())
        .await
        .into_auth_response()
}

#[utoipa::path(post, path = "/v1/refresh",
    tag="auth",
    responses(
        (status = 200, description = "Token refresh", content_type = "application/json", body = LoginResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn refresh(
    State(state): State<ServerState>,
    BearerToken(token): BearerToken,
) -> impl IntoResponse {
    state.auth_service.refresh(token).await.into_auth_response()
}

#[utoipa::path(post, path = "/v1/logout",
    tag="auth",
    responses(
        (status = 200, description = "Logout successful"),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn logout(
    State(state): State<ServerState>,
    BearerToken(token): BearerToken,
) -> impl IntoResponse {
    state.auth_service.logout(token).await.into_auth_response()
}
