use auth_service::api::routes::routes;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum_test::TestServer;
use sqlx::{MySql, Pool};

mod acceptance;
mod integration;
mod unit;

pub fn create_test_server(pool: Pool<MySql>) -> TestServer {
    let repository = MysqlUserRepository::new(pool);

    TestServer::new(routes(repository)).unwrap()
}
