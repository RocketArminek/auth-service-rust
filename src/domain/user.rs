use crate::domain::crypto::Hasher;
use crate::domain::error::UserError;
use chrono::{DateTime, Timelike, Utc};
use lazy_regex::regex;
use sqlx::{FromRow};
use uuid::{NoContext, Timestamp, Uuid};
use crate::domain::role::Role;

#[derive(FromRow, Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>
}

impl User {
    pub fn new(
        id: Uuid,
        email: String,
        password: String,
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
            Err(UserError::InvalidPassword)
        } else if !password_digit_check.is_match(&password) {
            Err(UserError::InvalidPassword)
        } else if !password_special_character_check.is_match(&password) {
            Err(UserError::InvalidPassword)
        } else if !password_uppercase_check.is_match(&password) {
            Err(UserError::InvalidPassword)
        } else if !password_lowercase_check.is_match(&password) {
            Err(UserError::InvalidPassword)
        } else if !email_regex.is_match(&email) {
            Err(UserError::InvalidEmail { email })
        } else {
            Ok(User {
                id,
                email,
                password,
                created_at,
            })
        }
    }

    pub fn now_with_email_and_password(email: String, password: String) -> Result<Self, UserError> {
        let now = Utc::now();
        let timestamp = Timestamp::from_unix(NoContext, now.timestamp() as u64, now.nanosecond());

        User::new(
            Uuid::new_v7(timestamp),
            email.clone(),
            password.clone(),
            now,
        )
    }
}

#[derive(Debug, Clone)]
pub struct UserWithRoles {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub roles: Vec<Role>,
}

impl Into<User> for UserWithRoles {
    fn into(self) -> User {
        User {
            id: self.id,
            email: self.email,
            password: self.password,
            created_at: self.created_at,
        }
    }
}

impl UserWithRoles {
    pub fn from_user(user: User) -> Self {
        Self::from_user_and_roles(user, vec![])
    }

    pub fn from_user_and_roles(user: User, roles: Vec<Role>) -> Self {
        UserWithRoles {
            id: user.id,
            email: user.email,
            password: user.password,
            created_at: user.created_at,
            roles,
        }
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

impl PasswordHandler for UserWithRoles {
    fn get_password(&self) -> String {
        self.password.clone()
    }

    fn set_password(&mut self, password: String) {
        self.password = password;
    }
}
