use crate::application::app_configuration::AppConfiguration;
use crate::domain::event::UserEvents;
use crate::domain::repositories::{RoleRepository, UserRepository};
use crate::infrastructure::message_publisher::MessagePublisher;
use std::sync::Arc;
use crate::application::auth_service::AuthService;

#[derive(Clone)]
pub struct ServerState {
    pub config: AppConfiguration,
    pub user_repository: Arc<dyn UserRepository>,
    pub role_repository: Arc<dyn RoleRepository>,
    pub message_publisher: Arc<dyn MessagePublisher<UserEvents>>,
    pub auth_service: Arc<dyn AuthService>,
}

impl ServerState {
    pub fn new(
        config: AppConfiguration,
        user_repository: Arc<dyn UserRepository>,
        role_repository: Arc<dyn RoleRepository>,
        message_publisher: Arc<dyn MessagePublisher<UserEvents>>,
        auth_service: Arc<dyn AuthService>,
    ) -> Self {
        ServerState {
            config,
            user_repository,
            role_repository,
            message_publisher,
            auth_service,
        }
    }
}

pub trait SecretAware {
    fn get_secret(&self) -> String;
}

pub trait VerificationRequired {
    fn get_verification_required(&self) -> bool;
}

pub trait AuthServiceAware {
    fn get_auth_service(&self) -> Arc<dyn AuthService>;
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

impl AuthServiceAware for ServerState {
    fn get_auth_service(&self) -> Arc<dyn AuthService> {
        self.auth_service.clone()
    }
}
