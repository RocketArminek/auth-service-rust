use axum_test::TestServer;
use auth_service::api::routes::routes;

mod acceptance;
mod integration;
mod unit;

pub fn create_test_server() -> TestServer {
    TestServer::new(routes()).unwrap()
}
