#[derive(Debug)]
pub enum Error {
    InvalidEmail { email: String },
    InvalidPassword,
    EncryptionFailed,
}

#[derive(Debug)]
pub enum StorageError {
    AlreadyExists { email: String },
}
