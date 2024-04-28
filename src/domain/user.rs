use crate::domain::cryptography::{BcryptHasher, Hasher};
use crate::domain::error::Error;
use chrono::{DateTime, Timelike, Utc};
use lazy_regex::regex;
use sqlx::FromRow;
use uuid::{NoContext, Timestamp, Uuid};

#[derive(FromRow, Debug)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn new(
        id: Uuid,
        email: String,
        password: String,
        created_at: DateTime<Utc>,
    ) -> Result<Self, Error> {
        let email_regex = regex!(r#"(?i)^[a-z0-9.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$"#);
        let password_digit_check = regex!(r#"\d"#);
        let password_special_character_check = regex!(r#"[@$!%*#?&]"#);
        let password_uppercase_check = regex!(r#"[A-Z]"#);
        let password_lowercase_check = regex!(r#"[a-z]"#);

        if email.is_empty() {
            Err(Error::InvalidEmail { email })
        } else if password.is_empty() {
            Err(Error::EmptyPassword)
        } else if password.len() < 8 {
            Err(Error::InvalidPassword)
        } else if !password_digit_check.is_match(&password) {
            Err(Error::InvalidPassword)
        } else if !password_special_character_check.is_match(&password) {
            Err(Error::InvalidPassword)
        } else if !password_uppercase_check.is_match(&password) {
            Err(Error::InvalidPassword)
        } else if !password_lowercase_check.is_match(&password) {
            Err(Error::InvalidPassword)
        } else if !email_regex.is_match(&email) {
            Err(Error::InvalidEmail { email })
        } else {
            Ok(User {
                id,
                email,
                password,
                created_at,
            })
        }
    }

    pub fn now_with_email_and_password(email: String, password: String) -> Result<Self, Error> {
        let now = Utc::now();
        let timestamp = Timestamp::from_unix(NoContext, now.timestamp() as u64, now.nanosecond());

        User::new(
            Uuid::new_v7(timestamp),
            email.clone(),
            password.clone(),
            now,
        )
    }

    pub fn hash_password(&mut self) {
        let hasher = BcryptHasher::new();
        let hashed_password = hasher.hash_password(self.password.as_str());

        self.password = hashed_password.unwrap();
    }
}
