use crate::api::ServerState;
use crate::domain::crypto::SchemeAwareHasher;
use crate::domain::user::User;
use axum::extract::State;
use axum::http::{StatusCode};
use axum::Json;
use crate::api::dto::{CreateUserRequest};

#[utoipa::path(post, path = "/v1/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created"),
        (status = 400, description = "Bad request", content_type = "application/json", body = MessageResponse),
    )
)]
pub async fn create_user(
    State(state): State<ServerState>,
    request: Json<CreateUserRequest>,
) -> StatusCode {
    let email = request.email.clone();
    let password = request.password.clone();
    let existing = state.repository
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
                    match state.repository.lock().await.add(&user).await {
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
