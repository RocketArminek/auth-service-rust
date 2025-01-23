#[derive(Debug)]
pub enum UserError {
    InvalidEmail { email: String },
    InvalidPassword { reason: Option<String> },
    EmptyPassword,
    EncryptionFailed,
    SchemeNotSupported,
}

#[derive(Debug)]
pub enum RoleError {
    Empty,
}

#[derive(Debug, PartialEq)]
pub enum PermissionError {
    EmptyName,
    EmptyGroupName,
}
