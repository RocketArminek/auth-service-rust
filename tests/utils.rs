use std::sync::Arc;
use axum_test::TestServer;
use sqlx::{MySql, Pool};
use tokio::sync::Mutex;
use auth_service::api::routes::routes;
use auth_service::api::server_state::{parse_restricted_pattern, ServerState};
use auth_service::domain::crypto::HashingScheme;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;

pub fn create_test_server(secret: String, pool: Pool<MySql>, hashing_scheme: HashingScheme) -> TestServer {
    let user_repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let restricted_role_pattern = parse_restricted_pattern("ADMIN").unwrap();
    let state = ServerState {
        secret,
        restricted_role_pattern,
        hashing_scheme,
        user_repository: Arc::new(Mutex::new(user_repository)),
        role_repository: Arc::new(Mutex::new(role_repository)),
    };

    TestServer::new(routes(state)).unwrap()
}
