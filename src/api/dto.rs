use serde::{Deserialize, Serialize};
use utoipa::{ToSchema};

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SessionResponse {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub token: TokenResponse
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct TokenResponse {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub email: String,
    pub token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: usize,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
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
