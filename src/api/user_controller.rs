use std::ops::Add;
use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::user::User;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{Duration, Timelike, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use tokio::sync::Mutex;
use utoipa::{ToResponse, ToSchema};
use uuid::{NoContext, Timestamp, Uuid};
use crate::api::ServerState;
use crate::domain::jwt::Claims;

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
            tokio::spawn(async move {
                user.hash_password(&SchemeAwareHasher::with_scheme(state.hashing_scheme));
                match thread_safe_repository.lock().await.add(&user).await {
                    Ok(_) => tracing::info!("User created: {}", user.email),
                    Err(error) => tracing::warn!("Failed to create user {:?}", error),
                }
            });

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
        (status = 200, description = "Get token", content_type = "application/json", body = LoginResponse),
        (status = 404, description = "User not found", content_type = "application/json", body = LoginResponse),
        (status = 401, description = "Unauthorized", content_type = "application/json", body = LoginResponse),
    )
)]
pub async fn login(
    State(state): State<ServerState>,
    request: Json<LoginRequest>,
) -> (StatusCode, Json<LoginResponse>) {
    let email = request.email.clone();
    let password = request.password.clone();
    let user = state.repository.get_by_email(&email).await;

    match user {
        Some(user) => {
            if !user.verify_password(&SchemeAwareHasher::with_scheme(state.hashing_scheme), &password) {
                return (StatusCode::UNAUTHORIZED, Json(
                    LoginResponse::Unauthorized(
                        ErrorResponse {
                            message: String::from("Unauthorized"),
                        }
                    )
                ))
            }

            let now = Utc::now();
            let exp = now.add(Duration::days(30));
            let timestamp = Timestamp::from_unix(NoContext, now.timestamp() as u64, now.nanosecond());

            let claims = Claims::new(
                user.id.to_string().clone(),
                exp.timestamp() as usize,
                "rocket-arminek".to_string(),
                user.email.clone(),
            );
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.secret.as_ref())
            );

            match token {
                Ok(token) => {
                    (StatusCode::OK, Json(
                        LoginResponse::OK(
                            SessionResponse {
                                session_id: Uuid::new_v7(timestamp).to_string(),
                                user_id: user.id.to_string(),
                                email: user.email,
                                token,
                                expires_at: exp.timestamp() as usize,
                            })
                        )
                    )
                }
                Err(_) => {
                    (StatusCode::FORBIDDEN, Json(
                        LoginResponse::Forbidden(
                            ErrorResponse {
                                message: String::from("Could not encode token"),
                            }
                        )
                    ))
                }
            }
        }
        None => (StatusCode::NOT_FOUND, Json(
            LoginResponse::NotFound(
                ErrorResponse {
                    message: String::from("User not found"),
                }
            )
        )),
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

#[derive(Debug, Deserialize, Serialize, ToResponse)]
pub enum LoginResponse {
    OK(SessionResponse),
    BadRequest(ErrorResponse),
    Unauthorized(ErrorResponse),
    NotFound(ErrorResponse),
    Forbidden(ErrorResponse),
}

#[derive(Debug, Deserialize, Serialize, ToResponse)]
#[response(description = "Session response")]
pub struct SessionResponse {
    pub session_id: String,
    pub user_id: String,
    pub email: String,
    pub token: String,
    pub expires_at: usize,
}

#[derive(Debug, Deserialize, Serialize, ToResponse)]
pub struct ErrorResponse {
    pub message: String,
}
