use crate::domain::user::User;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

pub async fn create_user(
    State(repository): State<MysqlUserRepository>,
    request: Json<CreateUserRequest>,
) -> StatusCode {
    let user = User::now_with_email_and_password(request.email.clone(), request.password.clone());

    match user {
        Ok(user) => {
            let result = repository.add(&user).await;
            if result.is_err() {
                return StatusCode::UNPROCESSABLE_ENTITY;
            }

            StatusCode::CREATED
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}
