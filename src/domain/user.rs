use uuid::{NoContext, Timestamp, Uuid};
use crate::domain::error::Error;
use chrono::{DateTime, Timelike, Utc};
use regex::Regex;
use sqlx::FromRow;

#[derive(FromRow, Debug)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn new(id: Uuid, email: String, password: String, created_at: DateTime<Utc>) -> Result<Self, Error> {
        if email.is_empty() {
            Err(Error::InvalidEmail{email})
        } else if !Regex::new(r"(?i)^[a-z0-9.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$").unwrap().is_match(&email) {
            Err(Error::InvalidEmail{email})
        } else {
            Ok(User { id, email, password, created_at })
        }
    }

    pub fn now_with_email_and_password(email: String, password: String) -> Result<Self, Error> {
        let now = Utc::now();
        let timestamp = Timestamp::from_unix(NoContext, now.timestamp() as u64, now.nanosecond());

        User::new(Uuid::new_v7(timestamp), email.clone(), password.clone(), now)
    }
}
