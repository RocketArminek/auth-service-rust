use auth_service::api::routes::*;
use auth_service::domain::crypto::HashingScheme;
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use dotenv::dotenv;
use sqlx::sqlx_macros::migrate;
use std::env;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    dotenv().ok();
    let secret = env::var("SECRET").expect("SECRET is not set in envs");
    let hashing_scheme =
        env::var("PASSWORD_HASHING_SCHEME").expect("PASSWORD_HASHING_SCHEME is not set in envs");
    let hashing_scheme = HashingScheme::from_string(hashing_scheme).unwrap();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let port = 8080;
    let addr = &format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(addr).await;

    let pool = create_mysql_pool().await.unwrap();
    migrate!("./migrations").run(&pool).await.unwrap();
    let repository = MysqlUserRepository::new(pool);

    match listener {
        Ok(listener) => {
            println!("Server started at {}", addr);
            axum::serve(listener, routes(secret, hashing_scheme, repository.clone()))
                .await
                .unwrap();
        }
        Err(e) => {
            println!("Failed to bind to port {}: {}", port, e);
        }
    }
}
