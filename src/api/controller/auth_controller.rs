use crate::api::dto::{LoginRequest, LoginResponse, MessageResponse};
use crate::api::extractor::auth_extractor::{BearerToken, LoggedInUser};
use crate::api::response::auth_response::IntoAuthResponse;
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
    state
        .auth_service
        .login(request.email.clone(), request.password.clone())
        .await
        .into_auth_response()
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
        HeaderValue::from_str(user_roles.as_str()).unwrap_or(HeaderValue::from_static("")),
    );

    let mut permission_strings: Vec<String> = user
        .permissions
        .iter()
        .flat_map(|(group, perms)| perms.iter().map(move |p| format!("{}:{}", group, p)))
        .collect();

    if !permission_strings.is_empty() {
        permission_strings.sort();

        headers.insert(
            "X-User-Permissions",
            HeaderValue::from_str(&permission_strings.join(","))
                .unwrap_or(HeaderValue::from_static("")),
        );
    }

    (StatusCode::OK, headers, Json(user)).into_response()
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
