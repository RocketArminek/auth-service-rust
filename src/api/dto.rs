use crate::domain::jwt::UserDTO;
use crate::domain::session::Session;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use axum::response::IntoResponse;
use axum::http::StatusCode;
use axum::Json;
use crate::application::service::auth_service::AuthError;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct UpdateUserRequest {
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
    #[serde(rename = "avatarPath")]
    pub avatar_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct VerifyUserRequest {
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ResetPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct TokenResponse {
    pub value: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: usize,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct LoginResponse {
    pub user: UserDTO,
    #[serde(rename = "accessToken")]
    pub access_token: TokenResponse,
    #[serde(rename = "refreshToken")]
    pub refresh_token: TokenResponse,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreatedResponse {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct UserListResponse {
    pub items: Vec<UserDTO>,
    pub page: i32,
    pub limit: i32,
    pub total: i32,
    pub pages: i32,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct Pagination {
    pub page: Option<i32>,
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SessionListResponse {
    pub items: Vec<Session>,
    pub total: i32,
    pub page: i32,
    pub limit: i32,
    pub pages: i32,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RoleListResponse {
    pub roles: Vec<RoleResponse>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AssignRoleRequest {
    pub role: String,
}

impl AuthError {
    pub fn into_message_response(self) -> (StatusCode, Json<MessageResponse>) {
        match self {
            AuthError::UserNotFound => (
                StatusCode::NOT_FOUND,
                Json(MessageResponse {
                    message: "User not found".to_string(),
                }),
            ),
            AuthError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Expired token".to_string(),
                }),
            ),
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Invalid credentials".to_string(),
                }),
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Invalid token".to_string(),
                }),
            ),
            AuthError::InvalidTokenType => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Invalid token type".to_string(),
                }),
            ),
            AuthError::InternalError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MessageResponse {
                    message: "Internal error".to_string(),
                }),
            ),
            AuthError::TokenEncodingFailed => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Token encoding failed".to_string(),
                }),
            ),
            AuthError::SessionNotFound => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Session not found".to_string(),
                }),
            ),
            AuthError::AuthStrategyNotSupported => (
                StatusCode::BAD_REQUEST,
                Json(MessageResponse {
                    message: "Action not supported in this strategy".to_string(),
                }),
            ),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        self.into_message_response().into_response()
    }
}
