use crate::application::configuration::app::AppConfiguration;
use crate::application::service::auth_service::AuthService;
use crate::domain::repository::PermissionRepository;
use crate::infrastructure::message_publisher::MessagePublisher;
use crate::infrastructure::role_repository::RoleRepository;
use crate::infrastructure::user_repository::UserRepository;
use std::sync::Arc;

#[derive(Clone)]
pub struct ServerState {
    pub config: AppConfiguration,
    pub user_repository: UserRepository,
    pub role_repository: RoleRepository,
    pub permission_repository: Arc<dyn PermissionRepository>,
    pub message_publisher: MessagePublisher,
    pub auth_service: AuthService,
}

impl ServerState {
    pub fn new(
        config: AppConfiguration,
        user_repository: UserRepository,
        role_repository: RoleRepository,
        permission_repository: Arc<dyn PermissionRepository>,
        message_publisher: MessagePublisher,
        auth_service: AuthService,
    ) -> Self {
        ServerState {
            config,
            user_repository,
            role_repository,
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
    fn get_auth_service(&self) -> &AuthService;
}

impl SecretAware for ServerState {
    fn get_secret(&self) -> String {
        self.config.secret().to_string()
    }
}

impl AuthServiceAware for ServerState {
    fn get_auth_service(&self) -> &AuthService {
        &self.auth_service
    }
}
