use crate::domain::user::User;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
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
    let user = User::now_with_email_and_password(request.email.clone(), request.password.clone());

    match user {
        Ok(mut user) => {
            tokio::spawn(async move {
                let r = repository.clone();
                user.hash_password();
                match r.add(&user).await {
                    Ok(_) => tracing::info!("User created: {}", user.email),
                    Err(error) => tracing::warn!("Failed to create user {:?}", error),
                }
            });

            StatusCode::OK
        },
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
