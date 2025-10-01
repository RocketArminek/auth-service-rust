use crate::application::configuration::app::AppConfiguration;
use crate::application::service::auth_service::AuthService;
use crate::domain::repository::{
    PermissionRepository, RoleRepository, SessionRepository, UserRepository,
};
use crate::infrastructure::message_publisher::MessagePublisher;
use std::sync::Arc;

#[derive(Clone)]
pub struct ServerState {
    pub config: AppConfiguration,
    pub user_repository: Arc<dyn UserRepository>,
    pub role_repository: Arc<dyn RoleRepository>,
    pub session_repository: Arc<dyn SessionRepository>,
    pub permission_repository: Arc<dyn PermissionRepository>,
    pub message_publisher: MessagePublisher,
    pub auth_service: Arc<dyn AuthService>,
}

impl ServerState {
    pub fn new(
        config: AppConfiguration,
        user_repository: Arc<dyn UserRepository>,
        role_repository: Arc<dyn RoleRepository>,
        session_repository: Arc<dyn SessionRepository>,
        permission_repository: Arc<dyn PermissionRepository>,
        message_publisher: MessagePublisher,
        auth_service: Arc<dyn AuthService>,
    ) -> Self {
        ServerState {
            config,
            user_repository,
            role_repository,
            session_repository,
            permission_repository,
            message_publisher,
            auth_service,
        }
    }
}

pub trait SecretAware {
    fn get_secret(&self) -> String;
}

pub trait AuthServiceAware {
    fn get_auth_service(&self) -> Arc<dyn AuthService>;
}

impl SecretAware for ServerState {
    fn get_secret(&self) -> String {
        self.config.secret().to_string()
    }
}

impl AuthServiceAware for ServerState {
    fn get_auth_service(&self) -> Arc<dyn AuthService> {
        self.auth_service.clone()
    }
}
