use crate::domain::crypto::HashingScheme;
use crate::infrastructure::message_publisher::MessagePublisher;
use crate::infrastructure::mysql_role_repository::MysqlRoleRepository;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;
use regex::{Error, Regex};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct ServerState {
    pub secret: String,
    pub hashing_scheme: HashingScheme,
    pub restricted_role_pattern: Regex,
    pub at_duration_in_seconds: i64,
    pub rt_duration_in_seconds: i64,
    pub verification_required: bool,
    pub user_repository: Arc<Mutex<MysqlUserRepository>>,
    pub role_repository: Arc<Mutex<MysqlRoleRepository>>,
    pub message_publisher: Arc<Mutex<dyn MessagePublisher + Send + Sync>>,
}

pub trait SecretAware {
    fn get_secret(&self) -> String;
}

impl SecretAware for ServerState {
    fn get_secret(&self) -> String {
        self.secret.clone()
    }
}

pub fn parse_restricted_pattern(pattern: &str) -> Result<Regex, Error> {
    Regex::new(format!("(?i)^{}.*", pattern).as_str())
}
