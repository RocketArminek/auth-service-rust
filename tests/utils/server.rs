use auth_service::api::routes::routes;
use auth_service::api::server_state::ServerState;
use auth_service::application::configuration::composed::Configuration;
use auth_service::application::service::auth_service::AuthService;
use auth_service::domain::repository::{PermissionRepository, RoleRepository, UserRepository};
use auth_service::infrastructure::message_publisher::MessagePublisher;
use axum_test::TestServer;
use std::sync::Arc;

pub async fn create_test_server(
    config: &Configuration,
    user_repository: Arc<dyn UserRepository>,
    role_repository: Arc<dyn RoleRepository>,
    permission_repository: Arc<dyn PermissionRepository>,
    message_publisher: MessagePublisher,
    auth_service: AuthService,
) -> TestServer {
    let config = config.app().clone();

    let state = ServerState::new(
        config,
        user_repository,
        role_repository,
        permission_repository,
        message_publisher,
        auth_service,
    );

    TestServer::new(routes(state)).unwrap()
}
