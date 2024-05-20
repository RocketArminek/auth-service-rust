use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub id: String,
    pub exp: usize,
    pub email: String,
    pub roles: Vec<String>,
}

impl Claims {
    pub fn new(id: String, exp: usize, email: String, roles: Vec<String>) -> Self {
        Self { id, email, exp, roles }
    }
}
