use auth_service::api::routes::routes;
use auth_service::api::server_state::ServerState;
use auth_service::application::configuration::composed::Configuration;
use auth_service::application::service::auth_service::AuthService;
use auth_service::domain::event::UserEvents;
use auth_service::domain::repository::{
    PermissionRepository, RoleRepository, SessionRepository, UserRepository,
};
use auth_service::infrastructure::message_publisher::MessagePublisher;
use axum_test::TestServer;
use std::sync::Arc;

pub async fn create_test_server(
    config: &Configuration,
    user_repository: Arc<dyn UserRepository>,
    role_repository: Arc<dyn RoleRepository>,
    session_repository: Arc<dyn SessionRepository>,
    permission_repository: Arc<dyn PermissionRepository>,
    message_publisher: Arc<dyn MessagePublisher<UserEvents>>,
    auth_service: Arc<dyn AuthService>,
) -> TestServer {
    let config = config.app().clone();

    let state = ServerState::new(
        config,
        user_repository,
        role_repository,
        session_repository,
        permission_repository,
        message_publisher,
        auth_service,
    );

    TestServer::new(routes(state)).unwrap()
}
