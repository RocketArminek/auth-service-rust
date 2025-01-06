use crate::domain::event::UserEvents;
use crate::domain::repositories::{RoleRepository, UserRepository};
use crate::infrastructure::message_publisher::MessagePublisher;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::application::app_configuration::AppConfiguration;

#[derive(Clone)]
pub struct ServerState {
    pub config: AppConfiguration,
    pub user_repository: Arc<Mutex<dyn UserRepository>>,
    pub role_repository: Arc<Mutex<dyn RoleRepository>>,
    pub message_publisher: Arc<Mutex<dyn MessagePublisher<UserEvents>>>,
}

impl ServerState {
    pub fn new(
        config: AppConfiguration,
        user_repository: Arc<Mutex<dyn UserRepository>>,
        role_repository: Arc<Mutex<dyn RoleRepository>>,
        message_publisher: Arc<Mutex<dyn MessagePublisher<UserEvents>>>,
    ) -> Self {
        ServerState {
            config,
            user_repository,
            role_repository,
            message_publisher,
        }
    }
}

pub trait SecretAware {
    fn get_secret(&self) -> String;
}

pub trait VerificationRequired {
    fn get_verification_required(&self) -> bool;
}

impl SecretAware for ServerState {
    fn get_secret(&self) -> String {
        self.config.secret().to_string()
    }
}

impl VerificationRequired for ServerState {
    fn get_verification_required(&self) -> bool {
        self.config.verification_required()
    }
}
