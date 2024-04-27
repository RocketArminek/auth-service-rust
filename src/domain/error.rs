#[derive(Debug)]
pub enum Error {
    InvalidEmail { email: String },
    InvalidPassword,
    EmptyPassword,
    EncryptionFailed,
}

#[derive(Debug)]
pub enum StorageError {
    AlreadyExists { email: String },
}
