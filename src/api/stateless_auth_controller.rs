use crate::api::axum_extractor::{StatelessLoggedInUser};
use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::jwt::Claims;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::Json;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::ops::Add;
use axum::response::IntoResponse;
use crate::api::dto::{LoginRequest, MessageResponse, TokenResponse, UserResponse};
use crate::api::server_state::ServerState;
use crate::domain::user::PasswordHandler;

#[utoipa::path(post, path = "/v1/stateless/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Get token", content_type = "application/json", body = TokenResponse),
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
    let user = state.user_repository.lock().await.get_by_email(&email).await;

    match user {
        Some(user) => {
            if !user.verify_password(
                &SchemeAwareHasher::with_scheme(state.hashing_scheme),
                &password,
            ) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(MessageResponse { message: String::from("Unauthorized") }),
                ).into_response();
            }

            let now = Utc::now();
            let exp = now.add(Duration::days(30));

            let claims = Claims::new(
                user.id.to_string().clone(),
                exp.timestamp() as usize,
                user.email.clone(),
            );
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.secret.as_ref()),
            );

            match token {
                Ok(token) => (
                    StatusCode::OK,
                    Json(TokenResponse {
                        user_id: user.id.to_string(),
                        email: user.email,
                        token,
                        expires_at: exp.timestamp() as usize,
                    }),
                ).into_response(),
                Err(_) => (
                    StatusCode::FORBIDDEN,
                    Json(MessageResponse { message: String::from("Could not encode token") }),
                ).into_response(),
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(MessageResponse { message: String::from("User not found") }),
        ).into_response(),
    }
}

#[utoipa::path(get, path = "/v1/stateless/verify",
    responses(
        (status = 200, description = "Token verified", content_type = "application/json", body = UserResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = MessageResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn verify(
    StatelessLoggedInUser(user): StatelessLoggedInUser,
) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    let user_id = user.id.to_string();
    headers.insert(
        "X-User-Id",
        HeaderValue::from_str(&user_id.as_str()).unwrap_or(HeaderValue::from_static("")),
    );

    (StatusCode::OK, headers, Json(UserResponse { id: user_id, email: user.email })).into_response()
}
