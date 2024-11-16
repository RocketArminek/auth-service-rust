use serde::{Deserialize, Serialize};
use crate::api::dto::UserDTO;

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
