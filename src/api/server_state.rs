use crate::domain::crypto::HashingScheme;
use crate::domain::event::UserEvents;
use crate::infrastructure::message_publisher::MessagePublisher;
use regex::{Error, Regex};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::domain::repositories::{RoleRepository, UserRepository};

#[derive(Clone)]
pub struct ServerState {
    pub secret: String,
    pub hashing_scheme: HashingScheme,
    pub restricted_role_pattern: Regex,
    pub at_duration_in_seconds: i64,
    pub rt_duration_in_seconds: i64,
    pub verification_required: bool,
    pub vr_duration_in_seconds: i64,
    pub user_repository: Arc<Mutex<dyn UserRepository + Send + Sync>>,
    pub role_repository: Arc<Mutex<dyn RoleRepository + Send + Sync>>,
    pub message_publisher: Arc<Mutex<dyn MessagePublisher<UserEvents> + Send + Sync>>,
}

pub trait SecretAware {
    fn get_secret(&self) -> String;
}

pub trait VerificationRequired {
    fn get_verification_required(&self) -> bool;
}

impl SecretAware for ServerState {
    fn get_secret(&self) -> String {
        self.secret.clone()
    }
}

impl VerificationRequired for ServerState {
    fn get_verification_required(&self) -> bool {
        self.verification_required
    }
}

pub fn parse_restricted_pattern(pattern: &str) -> Result<Regex, Error> {
    Regex::new(format!("(?i)^{}.*", pattern).as_str())
}
