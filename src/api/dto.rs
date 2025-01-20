use crate::domain::jwt::UserDTO;
use crate::domain::session::Session;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
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

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RemoveRoleRequest {
    pub role: String,
}
