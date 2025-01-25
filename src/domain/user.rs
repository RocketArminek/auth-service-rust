use crate::domain::crypto::Hasher;
use crate::domain::error::UserError;
use crate::domain::role::Role;
use chrono::{DateTime, Timelike, Utc};
use lazy_regex::regex;
use uuid::{NoContext, Timestamp, Uuid};

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub not_hashed_password: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub roles: Vec<Role>,
    pub avatar_path: Option<String>,
    pub is_verified: bool,
}

impl User {
    pub fn new(
        id: Uuid,
        email: String,
        not_hashed_password: String,
        first_name: Option<String>,
        last_name: Option<String>,
        created_at: DateTime<Utc>,
        is_verified: Option<bool>,
    ) -> Result<Self, UserError> {
        let email_regex = regex!(r#"(?i)^[a-z0-9.+_-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z0-9-]+$"#);
        let is_verified = is_verified.unwrap_or(false);

        Self::validate_password(&not_hashed_password)?;

        if email.is_empty() || !email_regex.is_match(&email) {
            Err(UserError::InvalidEmail { email })
        } else {
            Ok(User {
                id,
                email,
                not_hashed_password,
                password: "".to_string(),
                first_name,
                last_name,
                created_at,
                roles: vec![],
                avatar_path: None,
                is_verified,
            })
        }
    }

    pub fn now_with_email_and_password(
        email: String,
        not_hashed_password: String,
        first_name: Option<String>,
        last_name: Option<String>,
        is_verified: Option<bool>,
    ) -> Result<Self, UserError> {
        let now = Utc::now();
        let timestamp = Timestamp::from_unix(NoContext, now.timestamp() as u64, now.nanosecond());

        User::new(
            Uuid::new_v7(timestamp),
            email.clone(),
            not_hashed_password.clone(),
            first_name,
            last_name,
            now,
            is_verified,
        )
    }

    pub fn with_roles(mut self, roles: Vec<Role>) -> Self {
        self.roles = roles;
        self
    }

    pub fn add_role(&mut self, role: Role) {
        if self.roles.contains(&role) {
            return;
        }

        self.roles.push(role);
    }

    pub fn verify(&mut self) {
        self.is_verified = true;
    }

    pub fn revoke_verification(&mut self) {
        self.is_verified = false;
    }

    pub fn add_roles(&mut self, roles: Vec<Role>) {
        for role in roles.iter() {
            self.add_role(role.clone());
        }
    }

    pub fn has_role(&self, role_name: String) -> bool {
        self.roles.iter().any(|role| role.name == role_name)
    }

    pub fn change_password(
        &mut self,
        new_password: &str,
        hasher: &impl Hasher,
    ) -> Result<(), UserError> {
        Self::validate_password(new_password)?;
        self.password = hasher.hash_password(new_password)?;

        Ok(())
    }

    pub fn remove_role(&mut self, role: &Role) {
        self.roles.retain(|r| r.id != role.id);
    }

    pub fn remove_roles(&mut self, roles: &[Role]) {
        for role in roles {
            self.remove_role(role);
        }
    }

    fn validate_password(password: &str) -> Result<(), UserError> {
        let password_digit_check = regex!(r#"\d"#);
        let password_special_character_check = regex!(r#"[@$!%*#?&]"#);
        let password_uppercase_check = regex!(r#"[A-Z]"#);
        let password_lowercase_check = regex!(r#"[a-z]"#);

        if !password_digit_check.is_match(password) {
            return Err(UserError::InvalidPassword {
                reason: Some("Password must contain at least one digit".to_string()),
            });
        } else if !password_special_character_check.is_match(password) {
            return Err(UserError::InvalidPassword {
                reason: Some("Password must contain at least one special character".to_string()),
            });
        } else if !password_uppercase_check.is_match(password) {
            return Err(UserError::InvalidPassword {
                reason: Some("Password must contain at least one uppercase letter".to_string()),
            });
        } else if !password_lowercase_check.is_match(password) {
            return Err(UserError::InvalidPassword {
                reason: Some("Password must contain at least one lowercase letter".to_string()),
            });
        } else if password.is_empty() {
            return Err(UserError::EmptyPassword);
        } else if password.len() < 8 {
            return Err(UserError::InvalidPassword {
                reason: Some("Password must be at least 8 characters long".to_string()),
            });
        }

        Ok(())
    }
}

pub trait PasswordHandler {
    fn hash_password(&mut self, hasher: &impl Hasher) -> Result<(), UserError> {
        let hashed_password = hasher.hash_password(self.get_not_hashed_password().as_str())?;
        self.set_password(hashed_password);

        Ok(())
    }

    fn verify_password(&self, hasher: &impl Hasher, password: &str) -> bool {
        hasher.verify_password(password, self.get_password().as_str())
    }

    fn get_not_hashed_password(&self) -> String;
    fn get_password(&self) -> String;
    fn set_password(&mut self, password: String);
}

impl PasswordHandler for User {
    fn get_not_hashed_password(&self) -> String {
        self.not_hashed_password.clone()
    }

    fn get_password(&self) -> String {
        self.password.clone()
    }

    fn set_password(&mut self, password: String) {
        self.password = password;
    }
}
