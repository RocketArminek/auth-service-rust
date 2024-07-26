use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub id: String,
    pub exp: usize,
    pub email: String,
    pub roles: Vec<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_path: Option<String>,
}

impl Claims {
    pub fn new(
        id: String,
        exp: usize,
        email: String,
        roles: Vec<String>,
        first_name: Option<String>,
        last_name: Option<String>,
        avatar_path: Option<String>,
    ) -> Self {
        Self { id, email, exp, roles, first_name, last_name, avatar_path }
    }
}
