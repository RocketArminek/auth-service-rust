use auth_service::api::routes::*;
use auth_service::domain::crypto::HashingScheme;
use auth_service::infrastructure::database::create_mysql_pool;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use dotenv::dotenv;
use sqlx::sqlx_macros::migrate;
use std::env;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use auth_service::api::server_state::{parse_restricted_pattern, ServerState};
use auth_service::domain::role::Role;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;

#[tokio::main(flavor = "multi_thread", worker_threads=4)]
async fn main() {
    dotenv().ok();
    let secret = env::var("SECRET").expect("SECRET is not set in envs");
    let hashing_scheme =
        env::var("PASSWORD_HASHING_SCHEME").expect("PASSWORD_HASHING_SCHEME is not set in envs");
    let hashing_scheme = HashingScheme::from_string(hashing_scheme).unwrap();
    let restricted_role_prefix = env::var("RESTRICTED_ROLE_PREFIX")
        .unwrap_or("ADMIN".to_string());
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let port = "8080";
    let addr = &format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(addr).await;

    tracing::info!("Configured hashing scheme: {}", hashing_scheme.to_string());
    tracing::info!("Configured restricted role prefix: {}", restricted_role_prefix.as_str());

    let pool = create_mysql_pool().await.expect("Failed to connect & create db pool");
    let migration_result = migrate!("./migrations").run(&pool).await;
    match migration_result {
        Ok(_) => {
            tracing::info!("Database migration completed successfully");
        }
        Err(e) => {
            tracing::error!("Failed to migrate database: {}", e);
            panic!("Failed to migrate database");
        }
    }
    let user_repository = Arc::new(
        Mutex::new(MysqlUserRepository::new(pool.clone()))
    );
    let role_repository = Arc::new(
        Mutex::new(MysqlRoleRepository::new(pool.clone()))
    );
    let existing_normal_role = role_repository.lock()
        .await.get_by_name(&"USER".to_string())
        .await;

    if existing_normal_role.is_some() {
        let existing_normal_role = existing_normal_role.clone().unwrap();
        tracing::info!(
            "Found existing normal role: {}, {}, {}",
            existing_normal_role.id,
            existing_normal_role.name,
            existing_normal_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    if existing_normal_role.is_none() {
        let normal_role = Role::now("USER".to_string())
            .expect("Failed to create normal role");

        role_repository.lock()
            .await.add(&normal_role)
            .await.expect("Failed to create normal role");

        tracing::info!(
            "Created initial normal role: {}, {}, {}",
            normal_role.id,
            normal_role.name,
            normal_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    let existing_init_role = role_repository.lock()
        .await.get_by_name(&restricted_role_prefix)
        .await;

    if existing_init_role.is_some() {
        let existing_init_role = existing_init_role.clone().unwrap();
        tracing::info!(
            "Found existing restricted role base on pattern: {}, {}, {}",
            existing_init_role.id,
            existing_init_role.name,
            existing_init_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    if existing_init_role.is_none() {
        let restricted_init_role = Role::now(restricted_role_prefix.clone())
            .expect("Failed to create restricted role");

        role_repository.lock()
            .await.add(&restricted_init_role)
            .await.expect("Failed to create restricted role");

        tracing::info!(
            "Created initial restricted role base on pattern: {}, {}, {}",
            restricted_init_role.id,
            restricted_init_role.name,
            restricted_init_role.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }

    let restricted_role_pattern = parse_restricted_pattern(restricted_role_prefix.as_str())
        .unwrap();

    let state = ServerState {
        secret,
        hashing_scheme,
        restricted_role_pattern,
        user_repository,
        role_repository,
    };

    match listener {
        Ok(listener) => {
            tracing::info!("Server started at {}", addr);
            axum::serve(listener, routes(state))
                .with_graceful_shutdown(shutdown_signal())
                .await
                .expect("Failed to start server");
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
