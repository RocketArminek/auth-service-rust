#[derive(Debug)]
pub enum Error {
    InvalidEmail { email: String },
    InvalidPassword,
    EmptyPassword,
    EncryptionFailed,
    SchemeNotSupported,
}
