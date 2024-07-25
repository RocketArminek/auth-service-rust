use crate::api::axum_extractor::{StatelessLoggedInUser};
use crate::domain::crypto::{Hasher, SchemeAwareHasher};
use crate::domain::jwt::Claims;
use axum::extract::{State};
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
    tag="stateless",
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
            let hasher = SchemeAwareHasher::with_scheme(state.hashing_scheme);
            if !user.verify_password(
                &hasher,
                &password,
            ) {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(MessageResponse { message: String::from("Unauthorized") }),
                ).into_response();
            }
            if hasher.is_password_outdated(&user.password) {
                let mut outdated_user = user.clone();
                let scheme = state.hashing_scheme.clone();
                tokio::task::spawn(
                    async move {
                        tracing::warn!(
                            "Password hash outdated for {}({}), updating...",
                            &outdated_user.email,
                            &outdated_user.id
                        );
                        let new_password = SchemeAwareHasher::with_scheme(scheme)
                            .hash_password(&password).unwrap_or(outdated_user.password.clone());
                        outdated_user.set_password(new_password);
                        let outdated_user = outdated_user.into();
                        match state.user_repository.lock().await.update(&outdated_user).await {
                            Ok(_) => tracing::info!(
                                "Password updated for {}({})",
                                &outdated_user.email,
                                &outdated_user.id
                            ),
                            Err(e) => tracing::warn!("Could not update password hash {:?}", e),
                        }
                    }
                );
            }

            let now = Utc::now();
            let exp = now.add(Duration::days(30));

            let roles = user.roles.iter().map(|role| role.name.clone()).collect();
            let claims = Claims::new(
                user.id.to_string().clone(),
                exp.timestamp() as usize,
                user.email.clone(),
                roles,
                user.first_name.clone(),
                user.last_name.clone(),
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
    tag="stateless",
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
    let user_roles = user.roles.join(",");
    headers.insert(
        "X-User-Id",
        HeaderValue::from_str(&user_id.as_str()).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert(
        "X-User-Roles",
        HeaderValue::from_str(&user_roles.as_str()).unwrap_or(HeaderValue::from_static("")),
    );

    (StatusCode::OK, headers, Json(UserResponse {
        id: user_id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
    })).into_response()
}
