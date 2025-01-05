use crate::domain::event::UserEvents;
use crate::domain::repositories::{RoleRepository, UserRepository};
use crate::infrastructure::message_publisher::MessagePublisher;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::application::app_configuration::AppConfiguration;

#[derive(Clone)]
pub struct ServerState {
    config: AppConfiguration,
    user_repository: Arc<Mutex<dyn UserRepository>>,
    role_repository: Arc<Mutex<dyn RoleRepository>>,
    message_publisher: Arc<Mutex<dyn MessagePublisher<UserEvents>>>,
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

    pub fn config(&self) -> AppConfiguration {
        self.config.clone()
    }

    pub fn user_repository(&self) -> &Arc<Mutex<dyn UserRepository>> {
        &self.user_repository
    }

    pub fn role_repository(&self) -> &Arc<Mutex<dyn RoleRepository>> {
        &self.role_repository
    }

    pub fn message_publisher(&self) -> &Arc<Mutex<dyn MessagePublisher<UserEvents>>> {
        &self.message_publisher
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
