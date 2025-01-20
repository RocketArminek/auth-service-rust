use crate::domain::jwt::UserDTO;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum UserEvents {
    #[serde(rename = "user.created")]
    Created { user: UserDTO },
    #[serde(rename = "user.deleted")]
    Deleted { user: UserDTO },
    #[serde(rename = "user.updated")]
    Updated {
        #[serde(rename = "oldUser")]
        old_user: UserDTO,
        #[serde(rename = "newUser")]
        new_user: UserDTO,
    },
    #[serde(rename = "user.verificationRequested")]
    VerificationRequested { user: UserDTO, token: String },
    #[serde(rename = "user.verified")]
    Verified { user: UserDTO },
    #[serde(rename = "user.passwordResetRequested")]
    PasswordResetRequested { user: UserDTO, token: String },
    #[serde(rename = "user.passwordReset")]
    PasswordReset { user: UserDTO },
    #[serde(rename = "user.roleAssigned")]
    RoleAssigned { user: UserDTO, role: String },
    #[serde(rename = "user.roleRemoved")]
    RoleRemoved { user: UserDTO, role: String },
}
