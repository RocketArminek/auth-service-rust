use crate::application::configuration::app::AppConfiguration;
use crate::application::service::auth_service::AuthService;
use crate::application::service::token_service::TokenService;
use crate::infrastructure::message_publisher::MessagePublisher;
use crate::infrastructure::permission_repository::PermissionRepository;
use crate::infrastructure::role_repository::RoleRepository;
use crate::infrastructure::user_repository::UserRepository;

#[derive(Clone)]
pub struct ServerState {
    pub config: AppConfiguration,
    pub user_repository: UserRepository,
    pub role_repository: RoleRepository,
    pub permission_repository: PermissionRepository,
    pub message_publisher: MessagePublisher,
    pub auth_service: AuthService,
    pub token_service: TokenService,
}

impl ServerState {
    pub fn new(
        config: AppConfiguration,
        user_repository: UserRepository,
        role_repository: RoleRepository,
        permission_repository: PermissionRepository,
        message_publisher: MessagePublisher,
        auth_service: AuthService,
        token_service: TokenService,
    ) -> Self {
        ServerState {
            config,
            user_repository,
            role_repository,
            permission_repository,
            message_publisher,
            auth_service,
            token_service,
        }
    }
}

pub trait TokenServiceAware {
    fn get_token_service(&self) -> &TokenService;
}

pub trait AuthServiceAware {
    fn get_auth_service(&self) -> &AuthService;
}

impl TokenServiceAware for ServerState {
    fn get_token_service(&self) -> &TokenService {
        &self.token_service
    }
}

impl AuthServiceAware for ServerState {
    fn get_auth_service(&self) -> &AuthService {
        &self.auth_service
    }
}
