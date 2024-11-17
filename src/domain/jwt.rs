use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,
    pub user: UserDTO,
    pub token_type: TokenType
}

impl Claims {
    pub fn new(
        exp: usize,
        user: UserDTO,
        token_type: TokenType
    ) -> Self {
        Self { exp, user, token_type }
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
pub struct UserDTO {
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
