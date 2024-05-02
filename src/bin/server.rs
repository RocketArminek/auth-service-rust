use auth_service::api::routes::*;
use auth_service::domain::crypto::HashingScheme;
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use dotenv::dotenv;
use sqlx::sqlx_macros::migrate;
use std::env;
use tokio::signal;

#[tokio::main(flavor = "multi_thread", worker_threads=4)]
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

    tracing::info!("Configured hashing scheme: {}", hashing_scheme.to_string());

    match listener {
        Ok(listener) => {
            tracing::info!("Server started at {}", addr);
            axum::serve(listener, routes(secret, hashing_scheme, repository.clone()))
                .with_graceful_shutdown(shutdown_signal())
                .await
                .unwrap();
        }
        Err(e) => {
            tracing::error!("Failed to bind to port {}: {}", port, e);
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
        let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
