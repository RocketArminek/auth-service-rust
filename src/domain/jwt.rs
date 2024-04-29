use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iss: String,
    pub email: String,
}

impl Claims {
    pub fn new(sub: String, exp: usize, iss: String, email: String) -> Self {
        Self {
            sub,
            exp,
            iss,
            email,
        }
    }
}
