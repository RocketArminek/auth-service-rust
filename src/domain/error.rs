#[derive(Debug)]
pub enum UserError {
    InvalidEmail { email: String },
    InvalidPassword,
    EmptyPassword,
    EncryptionFailed,
    SchemeNotSupported,
}

#[derive(Debug)]
pub enum RoleError {
    Empty,
}
