use uuid::{NoContext, Timestamp, Uuid};
use crate::domain::error::Error;
use chrono::{DateTime, Utc};
use regex::Regex;

pub struct User {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub roles: Vec<String>,
}

impl User {
    pub fn new(id: Uuid, email: String, created_at: DateTime<Utc>) -> Result<Self, Error> {
        if email.is_empty() {
            Err(Error::InvalidEmail)
        } else if !Regex::new(r"(?i)^[a-z0-9.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$").unwrap().is_match(&email) {
            Err(Error::InvalidEmail)
        } else {
            Ok(User { id, email, created_at, roles: vec![String::from("ROLE_USER")] })
        }
    }

    pub fn now_with_email(email: String) -> Result<Self, Error> {
        let now = Utc::now();
        let timestamp = Timestamp::from_unix(NoContext, now.timestamp() as u64, 0);

        User::new(Uuid::new_v7(timestamp), email, now)
    }
}
