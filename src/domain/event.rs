use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum UserEvents {
    #[serde(rename = "user.created")]
    Created {
        email: String
    },
}
