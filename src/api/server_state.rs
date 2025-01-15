use crate::application::app_configuration::AppConfiguration;
use crate::domain::event::UserEvents;
use crate::domain::repositories::{RoleRepository, SessionRepository, UserRepository};
use crate::infrastructure::message_publisher::MessagePublisher;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct ServerState {
    pub config: AppConfiguration,
    pub user_repository: Arc<Mutex<dyn UserRepository>>,
    pub role_repository: Arc<Mutex<dyn RoleRepository>>,
    pub session_repository: Arc<Mutex<dyn SessionRepository>>,
    pub message_publisher: Arc<Mutex<dyn MessagePublisher<UserEvents>>>,
}

impl ServerState {
    pub fn new(
        config: AppConfiguration,
        user_repository: Arc<Mutex<dyn UserRepository>>,
        role_repository: Arc<Mutex<dyn RoleRepository>>,
        session_repository: Arc<Mutex<dyn SessionRepository>>,
        message_publisher: Arc<Mutex<dyn MessagePublisher<UserEvents>>>,
    ) -> Self {
        ServerState {
            config,
            user_repository,
            role_repository,
            session_repository,
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

pub trait SessionRepositoryAware {
    fn get_session_repository(&self) -> Arc<Mutex<dyn SessionRepository>>;
}

pub trait UserRepositoryAware {
    fn get_user_repository(&self) -> Arc<Mutex<dyn UserRepository>>;
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

impl SessionRepositoryAware for ServerState {
    fn get_session_repository(&self) -> Arc<Mutex<dyn SessionRepository>> {
        self.session_repository.clone()
    }
}

impl UserRepositoryAware for ServerState {
    fn get_user_repository(&self) -> Arc<Mutex<dyn UserRepository>> {
        self.user_repository.clone()
    }
}
