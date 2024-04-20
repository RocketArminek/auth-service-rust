use uuid::Uuid;

#[derive(Debug)]
pub enum Error {
    UserNotFound {
        id: Uuid,
    },
    UserAlreadyExists {
        email: String,
    },
    InvalidEmail {
        email: String,
    },
}
