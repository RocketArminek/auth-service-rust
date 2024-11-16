use serde::{Deserialize, Serialize};
use utoipa::{ToSchema};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub role: String
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
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct TokenResponse {
    pub value: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: usize
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct LoginResponse {
    pub user: UserResponse,
    #[serde(rename = "accessToken")]
    pub access_token: TokenResponse,
    #[serde(rename = "refreshToken")]
    pub refresh_token: TokenResponse,
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    #[serde(rename = "avatarPath")]
    pub avatar_path: Option<String>,
    pub roles: Vec<String>,
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
    pub items: Vec<UserResponse>,
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
