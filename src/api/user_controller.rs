use crate::domain::cryptography::SchemeAwareHasher;
use crate::domain::user::User;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use utoipa::ToSchema;

#[utoipa::path(post, path = "/v1/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "Create user"),
    )
)]
pub async fn create_user(
    State(repository): State<MysqlUserRepository>,
    request: Json<CreateUserRequest>,
) -> StatusCode {
    let email = request.email.clone();
    let password = request.password.clone();
    let thread_safe_repository = Arc::new(Mutex::new(repository.clone()));
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
                user.hash_password(&SchemeAwareHasher::default());
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

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}
