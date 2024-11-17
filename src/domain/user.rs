use crate::domain::crypto::Hasher;
use crate::domain::error::UserError;
use chrono::{DateTime, Timelike, Utc};
use lazy_regex::regex;
use uuid::{NoContext, Timestamp, Uuid};
use crate::domain::role::Role;

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub roles: Vec<Role>,
    pub avatar_path: Option<String>,
}

impl User {
    pub fn new(
        id: Uuid,
        email: String,
        password: String,
        first_name: Option<String>,
        last_name: Option<String>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, UserError> {
        let email_regex = regex!(r#"(?i)^[a-z0-9.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$"#);
        let password_digit_check = regex!(r#"\d"#);
        let password_special_character_check = regex!(r#"[@$!%*#?&]"#);
        let password_uppercase_check = regex!(r#"[A-Z]"#);
        let password_lowercase_check = regex!(r#"[a-z]"#);

        if email.is_empty() {
            Err(UserError::InvalidEmail { email })
        } else if password.is_empty() {
            Err(UserError::EmptyPassword)
        } else if password.len() < 8 {
            Err(UserError::InvalidPassword { reason: Some("Password must be at least 8 characters long".to_string()) })
        } else if !password_digit_check.is_match(&password) {
            Err(UserError::InvalidPassword { reason: Some("Password must contain at least one digit".to_string()) })
        } else if !password_special_character_check.is_match(&password) {
            Err(UserError::InvalidPassword { reason: Some("Password must contain at least one special character".to_string()) })
        } else if !password_uppercase_check.is_match(&password) {
            Err(UserError::InvalidPassword { reason: Some("Password must contain at least one uppercase letter".to_string()) })
        } else if !password_lowercase_check.is_match(&password) {
            Err(UserError::InvalidPassword { reason: Some("Password must contain at least one lowercase letter".to_string()) })
        } else if !email_regex.is_match(&email) {
            Err(UserError::InvalidEmail { email })
        } else {
            Ok(User {
                id,
                email,
                password,
                first_name,
                last_name,
                created_at,
                roles: vec![],
                avatar_path: None,
            })
        }
    }

    pub fn now_with_email_and_password(
        email: String,
        password: String,
        first_name: Option<String>,
        last_name: Option<String>,
    ) -> Result<Self, UserError> {
        let now = Utc::now();
        let timestamp = Timestamp::from_unix(
            NoContext,
            now.timestamp() as u64,
            now.nanosecond()
        );

        User::new(
            Uuid::new_v7(timestamp),
            email.clone(),
            password.clone(),
            first_name,
            last_name,
            now,
        )
    }

    pub fn with_roles(mut self, roles: Vec<Role>) -> Self {
        self.roles = roles;
        self
    }

    pub fn add_role(&mut self, role: Role) {
        self.roles.push(role);
    }

    pub fn has_role(&self, role_name: String) -> bool {
        self.roles.iter().any(|role| role.name == role_name)
    }
}

pub trait PasswordHandler {
    fn hash_password(&mut self, hasher: &impl Hasher) {
        let hashed_password = hasher.hash_password(self.get_password().as_str());

        match hashed_password {
            Ok(hashed_password) => self.set_password(hashed_password),
            Err(error) => tracing::error!("Error hashing password: {:?}", error),
        }
    }

    fn verify_password(&self, hasher: &impl Hasher, password: &str) -> bool {
        hasher.verify_password(password, self.get_password().as_str())
    }

    fn get_password(&self) -> String;
    fn set_password(&mut self, password: String);
}

impl PasswordHandler for User {
    fn get_password(&self) -> String {
        self.password.clone()
    }

    fn set_password(&mut self, password: String) {
        self.password = password;
    }
}
