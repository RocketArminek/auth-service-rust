use auth_service::api::routes::routes;
use axum_test::TestServer;

pub fn create_test_server() -> TestServer {
    TestServer::new(routes()).unwrap()
}
