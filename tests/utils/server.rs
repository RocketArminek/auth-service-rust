use auth_service::api::routes::routes;
use auth_service::api::server_state::ServerState;
use auth_service::application::auth_service::AuthService;
use auth_service::application::configuration::Configuration;
use auth_service::domain::event::UserEvents;
use auth_service::domain::repositories::{RoleRepository, SessionRepository, UserRepository};
use auth_service::infrastructure::message_publisher::MessagePublisher;
use axum_test::TestServer;
use std::sync::Arc;

pub async fn create_test_server(
    config: &Configuration,
    user_repository: Arc<dyn UserRepository>,
    role_repository: Arc<dyn RoleRepository>,
    session_repository: Arc<dyn SessionRepository>,
    message_publisher: Arc<dyn MessagePublisher<UserEvents>>,
    auth_service: Arc<dyn AuthService>,
) -> TestServer {
    let config = config.app().clone();

    let state = ServerState::new(
        config,
        user_repository,
        role_repository,
        session_repository,
        message_publisher,
        auth_service,
    );

    TestServer::new(routes(state)).unwrap()
}
