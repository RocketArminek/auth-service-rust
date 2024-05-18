use std::sync::Arc;
use axum_test::TestServer;
use sqlx::{MySql, Pool};
use tokio::sync::Mutex;
use auth_service::api::routes::routes;
use auth_service::api::ServerState;
use auth_service::domain::crypto::HashingScheme;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;

pub fn create_test_server(secret: String, pool: Pool<MySql>) -> TestServer {
    let repository = MysqlUserRepository::new(pool);
    let state = ServerState {
        secret,
        hashing_scheme: HashingScheme::BcryptLow,
        repository: Arc::new(Mutex::new(repository)),
    };

    TestServer::new(routes(state)).unwrap()
}
