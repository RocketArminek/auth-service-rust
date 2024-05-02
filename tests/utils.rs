use axum_test::TestServer;
use sqlx::{MySql, Pool};
use auth_service::api::routes::routes;
use auth_service::domain::crypto::HashingScheme;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;

pub fn create_test_server(secret: String, pool: Pool<MySql>) -> TestServer {
    let repository = MysqlUserRepository::new(pool);

    TestServer::new(routes(secret, HashingScheme::BcryptLow, repository)).unwrap()
}