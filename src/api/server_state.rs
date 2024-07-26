use std::sync::Arc;
use regex::{Error, Regex};
use tokio::sync::Mutex;
use crate::domain::crypto::HashingScheme;
use crate::infrastructure::mysql_role_repository::MysqlRoleRepository;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;
use crate::infrastructure::s3_avatar_uploader::{S3AvatarUploader};

#[derive(Clone)]
pub struct ServerState {
    pub secret: String,
    pub hashing_scheme: HashingScheme,
    pub restricted_role_pattern: Regex,
    pub user_repository: Arc<Mutex<MysqlUserRepository>>,
    pub role_repository: Arc<Mutex<MysqlRoleRepository>>,
    pub avatar_uploader: Arc<Mutex<S3AvatarUploader>>,
}

pub trait UserRepositoryAware {
    fn get_user_repository(&self) -> Arc<Mutex<MysqlUserRepository>>;
}

pub trait RoleRepositoryAware {
    fn get_role_repository(&self) -> Arc<Mutex<MysqlRoleRepository>>;
}

pub trait RestrictedRolePatternAware {
    fn get_restricted_role_pattern(&self) -> Regex;
}

pub trait HashingSchemeAware {
    fn get_hashing_scheme(&self) -> HashingScheme;
}

pub trait SecretAware {
    fn get_secret(&self) -> String;
}

pub trait AvatarUploaderAware {
    fn get_avatar_uploader(&self) -> Arc<Mutex<S3AvatarUploader>>;
}

impl AvatarUploaderAware for ServerState {
    fn get_avatar_uploader(&self) -> Arc<Mutex<S3AvatarUploader>> {
        self.avatar_uploader.clone()
    }
}

impl SecretAware for ServerState {
    fn get_secret(&self) -> String {
        self.secret.clone()
    }
}

impl HashingSchemeAware for ServerState {
    fn get_hashing_scheme(&self) -> HashingScheme {
        self.hashing_scheme.clone()
    }
}

impl RestrictedRolePatternAware for ServerState {
    fn get_restricted_role_pattern(&self) -> Regex {
        self.restricted_role_pattern.clone()
    }
}

impl UserRepositoryAware for ServerState {
    fn get_user_repository(&self) -> Arc<Mutex<MysqlUserRepository>> {
        self.user_repository.clone()
    }
}

impl RoleRepositoryAware for ServerState {
    fn get_role_repository(&self) -> Arc<Mutex<MysqlRoleRepository>> {
        self.role_repository.clone()
    }
}

pub fn parse_restricted_pattern(pattern: &str) -> Result<Regex, Error> {
    Regex::new(format!("(?i)^{}.*", pattern).as_str())
}
