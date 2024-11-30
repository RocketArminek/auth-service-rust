use crate::domain::jwt::UserDTO;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum UserEvents {
    #[serde(rename = "user.created")]
    Created {
        user: UserDTO,
    },
    Deleted {
        user: UserDTO,
    },
    Updated {
        #[serde(rename = "oldUser")]
        old_user: UserDTO,
        #[serde(rename = "newUser")]
        new_user: UserDTO,
    },
}
