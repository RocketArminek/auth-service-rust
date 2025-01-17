use crate::api::axum_extractor::{BearerToken, LoggedInUser};
use crate::api::dto::{LoginRequest, LoginResponse, MessageResponse, TokenResponse};
use crate::api::server_state::ServerState;
use crate::domain::jwt::UserDTO;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

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
    let email = request.email.clone();
    let password = request.password.clone();

    let result = state.auth_service.login(email, password).await;

    match result {
        Ok((tokens, user)) => (
            StatusCode::OK,
            Json(LoginResponse {
                user,
                refresh_token: TokenResponse {
                    value: tokens.refresh_token.value,
                    expires_at: tokens.refresh_token.expires_at,
                },
                access_token: TokenResponse {
                    value: tokens.access_token.value,
                    expires_at: tokens.access_token.expires_at,
                },
            }),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

#[utoipa::path(get, path = "/v1/authenticate",
    tag="auth",
    responses(
        (status = 200, description = "Token verified", content_type = "application/json", body = UserDTO),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn authenticate(LoggedInUser(user): LoggedInUser) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    let user_id = user.id;
    let user_roles = user.roles.join(",");
    headers.insert(
        "X-User-Id",
        HeaderValue::from_str(&user_id.to_string()).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert(
        "X-User-Roles",
        HeaderValue::from_str(&user_roles.as_str()).unwrap_or(HeaderValue::from_static("")),
    );

    (StatusCode::OK, headers, Json(UserDTO::from(user))).into_response()
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
    let result = state.auth_service.refresh(token).await;
    match result {
        Ok((tokens, user)) => (
            StatusCode::OK,
            Json(LoginResponse {
                user,
                refresh_token: TokenResponse {
                    value: tokens.refresh_token.value,
                    expires_at: tokens.refresh_token.expires_at,
                },
                access_token: TokenResponse {
                    value: tokens.access_token.value,
                    expires_at: tokens.access_token.expires_at,
                },
            }),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}
