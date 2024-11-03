use std::sync::Arc;
use axum_test::TestServer;
use sqlx::{MySql, Pool};
use tokio::sync::Mutex;
use auth_service::api::routes::routes;
use auth_service::api::server_state::{parse_restricted_pattern, ServerState};
use auth_service::domain::crypto::HashingScheme;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;

pub fn create_test_server(
    secret: String,
    pool: Pool<MySql>,
    hashing_scheme: HashingScheme,
    restricted_pattern: Option<String>
) -> TestServer {
    let user_repository = Arc::new(
        Mutex::new(MysqlUserRepository::new(pool.clone()))
    );
    let role_repository = Arc::new(
        Mutex::new(MysqlRoleRepository::new(pool.clone()))
    );
    let restricted_role_pattern = parse_restricted_pattern(
        &restricted_pattern.unwrap_or("ADMIN".to_string())
    ).unwrap();

    let state = ServerState {
        secret,
        restricted_role_pattern,
        hashing_scheme,
        user_repository,
        role_repository,
    };

    TestServer::new(routes(state)).unwrap()
}
