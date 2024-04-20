#[derive(Debug)]
pub enum Error {
    UserNotFound,
    UserAlreadyExists,
    InvalidEmail,
    InvalidRole,
}
