use auth_service::api::routes::routes;
use auth_service::api::server_state::ServerState;
use auth_service::application::configuration::Configuration;
use auth_service::domain::event::UserEvents;
use auth_service::domain::repositories::{RoleRepository, UserRepository};
use auth_service::infrastructure::message_publisher::MessagePublisher;
use axum_test::TestServer;
use std::sync::Arc;

pub async fn create_test_server(
    config: &Configuration,
    user_repository: Arc<dyn UserRepository>,
    role_repository: Arc<dyn RoleRepository>,
    message_publisher: Arc<dyn MessagePublisher<UserEvents>>,
) -> TestServer {
    let config = config.app().clone();

    let state = ServerState::new(config, user_repository, role_repository, message_publisher);

    TestServer::new(routes(state)).unwrap()
}
