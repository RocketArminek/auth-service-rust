use crate::domain::permission::Permission;
use crate::domain::user::User;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    Access,
    Refresh,
    Verification,
    Password,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,
    pub user: UserDTO,
    pub token_type: TokenType,
    pub session_id: Option<Uuid>,
}

impl Claims {
    pub fn new(exp: usize, user: UserDTO, token_type: TokenType, session_id: Option<Uuid>) -> Self {
        Self {
            exp,
            user,
            token_type,
            session_id,
        }
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
    pub permissions: HashMap<String, Vec<String>>,
    #[serde(rename = "isVerified")]
    pub is_verified: bool,
}

impl From<User> for UserDTO {
    fn from(user: User) -> Self {
        UserDTO {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            avatar_path: user.avatar_path,
            roles: user.roles.iter().map(|role| role.name.clone()).collect(),
            permissions: HashMap::new(),
            is_verified: user.is_verified,
        }
    }
}

impl From<(User, Vec<Permission>)> for UserDTO {
    fn from((user, permissions): (User, Vec<Permission>)) -> Self {
        let mut permissions_map: HashMap<String, Vec<String>> = HashMap::new();

        for permission in permissions {
            permissions_map
                .entry(permission.group_name)
                .or_default()
                .push(permission.name);
        }

        UserDTO {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            avatar_path: user.avatar_path,
            roles: user.roles.iter().map(|role| role.name.clone()).collect(),
            permissions: permissions_map,
            is_verified: user.is_verified,
        }
    }
}
