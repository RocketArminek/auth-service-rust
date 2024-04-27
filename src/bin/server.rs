use auth_service::api::routes::*;
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use dotenv::dotenv;
use sqlx::sqlx_macros::migrate;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    dotenv().ok();

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
            axum::serve(listener, routes(repository.clone()))
                .await
                .unwrap();
        }
        Err(e) => {
            println!("Failed to bind to port {}: {}", port, e);
        }
    }
}
