use uuid::Uuid;
use crate::domain::error::Error;

pub struct User {
    pub id: Uuid,
    pub email: String,
    pub roles: Vec<String>,
}

impl User {
    pub fn new(email: String) -> Result<Self, Error> {
        if email.is_empty() {
            Err(Error::InvalidEmail)
        } else {
            Ok(User {
                id: Uuid::new_v4(),
                email,
                roles: vec![String::from("ROLE_USER")],
            })
        }
    }
}
