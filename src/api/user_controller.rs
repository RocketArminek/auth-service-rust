use crate::api::token_extractor::BearerToken;
use crate::api::ServerState;
use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::jwt::Claims;
use crate::domain::user::User;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use chrono::{Duration, Timelike, Utc};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::ops::Add;
use std::sync::Arc;
use axum::response::IntoResponse;
use tokio::sync::Mutex;
use utoipa::{ToResponse, ToSchema};
use uuid::{NoContext, Timestamp, Uuid};

#[utoipa::path(post, path = "/v1/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "Create user"),
    )
)]
pub async fn create_user(
    State(state): State<ServerState>,
    request: Json<CreateUserRequest>,
) -> StatusCode {
    let email = request.email.clone();
    let password = request.password.clone();
    let thread_safe_repository = Arc::new(Mutex::new(state.repository.clone()));
    let existing = thread_safe_repository
        .lock()
        .await
        .get_by_email(&email)
        .await;

    if existing.is_some() {
        return StatusCode::CONFLICT;
    }

    let user = User::now_with_email_and_password(email, password);

    match user {
        Ok(mut user) => {
            tokio::task::spawn(
                async move {
                    user.hash_password(&SchemeAwareHasher::with_scheme(state.hashing_scheme));
                    match thread_safe_repository.lock().await.add(&user).await {
                        Ok(_) => tracing::info!("User created: {}", user.email),
                        Err(error) => tracing::warn!("Failed to create user {:?}", error),
                    }
                }
            );

            StatusCode::OK
        }
        Err(error) => {
            tracing::info!("Failed to create user {:?}", error);

            StatusCode::BAD_REQUEST
        }
    }
}

#[utoipa::path(post, path = "/v1/users/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Get token", content_type = "application/json", body = AuthResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = AuthResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = AuthResponse),
    )
)]
pub async fn login(
    State(state): State<ServerState>,
    request: Json<LoginRequest>,
) -> impl IntoResponse {
    let email = request.email.clone();
    let password = request.password.clone();
    let user = state.repository.get_by_email(&email).await;

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
            let timestamp =
                Timestamp::from_unix(NoContext, now.timestamp() as u64, now.nanosecond());

            let claims = Claims::new(
                user.id.to_string().clone(),
                exp.timestamp() as usize,
                "rocket-arminek".to_string(),
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
                    Json(SessionResponse {
                        session_id: Uuid::new_v7(timestamp).to_string(),
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

#[utoipa::path(get, path = "/v1/users/verify",
    responses(
        (status = 200, description = "Token verified", content_type = "application/json", body = AuthResponse),
        (status = 403, description = "Forbidden", content_type = "application/json", body = AuthResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = AuthResponse),
    )
)]
pub async fn verify(
    BearerToken(token): BearerToken,
    State(state): State<ServerState>,
) -> impl IntoResponse {
    let decoded = jsonwebtoken::decode::<Claims>(
        &token,
        &DecodingKey::from_secret(state.secret.as_ref()),
        &Validation::default(),
    );
    let mut headers = HeaderMap::new();

    match decoded {
        Ok(decoded_token) => {
            let user_id = decoded_token.claims.sub.clone();
            let now = Utc::now();
            headers.insert(
                "X-User-Id",
                header::HeaderValue::from_str(&user_id).unwrap_or(header::HeaderValue::from_static("")),
            );

            (StatusCode::OK,
             headers,
             Json(
                 SessionResponse {
                     session_id: Uuid::new_v7(Timestamp::from_unix(
                         NoContext,
                         now.timestamp() as u64,
                         now.nanosecond(),
                     )).to_string(),
                     user_id,
                     email: decoded_token.claims.email,
                     token,
                     expires_at: decoded_token.claims.exp,
                 }
             )).into_response()
        }
        Err(error) => match error.kind() {
            ErrorKind::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                headers,
                Json(MessageResponse { message: String::from("Invalid token") }),
            ).into_response(),
            ErrorKind::InvalidSignature => (
                StatusCode::UNAUTHORIZED,
                headers,
                Json(MessageResponse { message: String::from("Invalid signature") }),
            ).into_response(),
            ErrorKind::ExpiredSignature => (
                StatusCode::UNAUTHORIZED,
                headers,
                Json(MessageResponse { message: String::from("Expired token") }),
            ).into_response(),
            _ => (
                StatusCode::UNAUTHORIZED,
                headers,
                Json(MessageResponse { message: String::from("Unauthorized") }),
            ).into_response(),
        },
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, ToResponse, ToSchema)]
#[response(description = "Session response")]
pub struct SessionResponse {
    pub session_id: String,
    pub user_id: String,
    pub email: String,
    pub token: String,
    pub expires_at: usize,
}

#[derive(Debug, Deserialize, Serialize, ToResponse, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}
