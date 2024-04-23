#[derive(Debug)]
pub enum Error {
    InvalidEmail { email: String },
}

#[derive(Debug)]
pub enum StorageError {
    AlreadyExists { email: String },
}
