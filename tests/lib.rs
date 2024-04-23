use auth_service::api::routes::routes;
use axum_test::TestServer;

mod acceptance;
mod integration;
mod unit;

pub fn create_test_server() -> TestServer {
    TestServer::new(routes()).unwrap()
}
