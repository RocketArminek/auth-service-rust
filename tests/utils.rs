#[cfg(feature = "mysql")]
use auth_service::domain::repositories::{RoleRepository, UserRepository};
#[cfg(feature = "mysql")]
use auth_service::infrastructure::database::{
    create_mysql_pool, create_sqlite_pool, get_database_engine, get_mysql_database_url,
    get_sqlite_db_url, DatabaseEngine, DatabasePool,
};
#[cfg(feature = "mysql")]
use auth_service::infrastructure::repository::{create_role_repository, create_user_repository};
#[cfg(feature = "mysql")]
use dotenv::{dotenv, from_filename};
use futures_lite::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties, Consumer, ExchangeKind};
use serde::{Deserialize, Serialize};
#[cfg(feature = "mysql")]
use sqlx::migrate::MigrateDatabase;
#[cfg(feature = "mysql")]
use sqlx::{Error, Sqlite};
use std::env;
use std::time::Duration;
use tokio::time::sleep;
#[cfg(feature = "mysql")]
use uuid::Uuid;
#[cfg(feature = "mysql")]
use auth_service::api::routes::routes;
#[cfg(feature = "mysql")]
use auth_service::api::server_state::{parse_restricted_pattern, ServerState};
#[cfg(feature = "mysql")]
use auth_service::domain::crypto::HashingScheme;
#[cfg(feature = "mysql")]
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
#[cfg(feature = "mysql")]
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
#[cfg(feature = "mysql")]
use auth_service::infrastructure::rabbitmq_message_publisher::RabbitmqMessagePublisher;
#[cfg(feature = "mysql")]
use axum_test::TestServer;
#[cfg(feature = "mysql")]
use sqlx::{MySql, Pool};
#[cfg(feature = "mysql")]
use std::sync::Arc;
#[cfg(feature = "mysql")]
use tokio::sync::Mutex;

#[cfg(feature = "mysql")]
pub async fn create_test_server_v2(
    secret: String,
    user_repository: Arc<Mutex<dyn UserRepository>>,
    role_repository: Arc<Mutex<dyn RoleRepository>>,
    hashing_scheme: HashingScheme,
    restricted_pattern: Option<String>,
    at_duration_in_seconds: i64,
    rt_duration_in_seconds: i64,
    verification_required: bool,
    vr_duration_in_seconds: i64,
    exchange_name: String,
) -> TestServer {
    let restricted_role_pattern =
        parse_restricted_pattern(&restricted_pattern.unwrap_or("ADMIN".to_string())).unwrap();
    let rabbitmq_url = env::var("RABBITMQ_URL").unwrap_or("amqp://localhost:5672".to_string());

    let rabbitmq_conn = Connection::connect(&rabbitmq_url, ConnectionProperties::default())
        .await
        .expect("Can't connect to RabbitMQ");
    let message_publisher = RabbitmqMessagePublisher::new(
        &rabbitmq_conn,
        exchange_name,
        ExchangeKind::Fanout,
        ExchangeDeclareOptions {
            durable: false,
            auto_delete: true,
            ..ExchangeDeclareOptions::default()
        },
    )
    .await
    .expect("Failed to create RabbitMQ message publisher");

    let message_publisher = Arc::new(Mutex::new(message_publisher));

    let state = ServerState {
        secret,
        restricted_role_pattern,
        hashing_scheme,
        at_duration_in_seconds,
        rt_duration_in_seconds,
        verification_required,
        vr_duration_in_seconds,
        user_repository,
        role_repository,
        message_publisher,
    };

    TestServer::new(routes(state)).unwrap()
}

#[cfg(feature = "mysql")]
pub async fn create_test_server(
    secret: String,
    pool: Pool<MySql>,
    hashing_scheme: HashingScheme,
    restricted_pattern: Option<String>,
    at_duration_in_seconds: i64,
    rt_duration_in_seconds: i64,
    verification_required: bool,
    vr_duration_in_seconds: i64,
    exchange_name: String,
) -> TestServer {
    let user_repository = Arc::new(Mutex::new(MysqlUserRepository::new(pool.clone())));
    let role_repository = Arc::new(Mutex::new(MysqlRoleRepository::new(pool.clone())));
    let restricted_role_pattern =
        parse_restricted_pattern(&restricted_pattern.unwrap_or("ADMIN".to_string())).unwrap();
    let rabbitmq_url = env::var("RABBITMQ_URL").unwrap_or("amqp://localhost:5672".to_string());

    let rabbitmq_conn = Connection::connect(&rabbitmq_url, ConnectionProperties::default())
        .await
        .expect("Can't connect to RabbitMQ");
    let message_publisher = RabbitmqMessagePublisher::new(
        &rabbitmq_conn,
        exchange_name,
        ExchangeKind::Fanout,
        ExchangeDeclareOptions {
            durable: false,
            auto_delete: true,
            ..ExchangeDeclareOptions::default()
        },
    )
    .await
    .expect("Failed to create RabbitMQ message publisher");

    let message_publisher = Arc::new(Mutex::new(message_publisher));

    let state = ServerState {
        secret,
        restricted_role_pattern,
        hashing_scheme,
        at_duration_in_seconds,
        rt_duration_in_seconds,
        verification_required,
        vr_duration_in_seconds,
        user_repository,
        role_repository,
        message_publisher,
    };

    TestServer::new(routes(state)).unwrap()
}

pub async fn setup_test_consumer(exchange_name: &str) -> (Channel, Consumer, String) {
    let rabbitmq_url = env::var("RABBITMQ_URL").unwrap_or("amqp://127.0.0.1:5672".to_string());

    let conn = Connection::connect(
        &rabbitmq_url,
        ConnectionProperties::default().with_connection_name("test_consumer".into()),
    )
    .await
    .expect("Failed to connect to RabbitMQ");

    let channel = conn
        .create_channel()
        .await
        .expect("Failed to create channel");

    channel
        .exchange_declare(
            exchange_name,
            ExchangeKind::Fanout,
            ExchangeDeclareOptions {
                durable: false,
                auto_delete: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("Failed to declare exchange");

    let queue = channel
        .queue_declare(
            "",
            QueueDeclareOptions {
                exclusive: true,
                auto_delete: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .expect("Failed to declare queue");

    let queue_name = queue.name().to_string();

    channel
        .queue_bind(
            &queue_name,
            exchange_name,
            "",
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("Failed to bind queue");

    let consumer = channel
        .basic_consume(
            &queue_name,
            "test_consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .expect("Failed to create consumer");

    (channel, consumer, queue_name)
}

pub async fn wait_for_event<T: std::fmt::Debug>(
    mut consumer: Consumer,
    timeout_secs: u64,
    predicate: impl Fn(&T) -> bool,
) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    let timeout = sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    tokio::select! {
        _ = &mut timeout => {
            println!("Timeout waiting for event");
            None
        }
        result = async {
            while let Some(delivery) = consumer.next().await {
                match delivery {
                    Ok(delivery) => {
                        if let Ok(event) = serde_json::from_slice::<T>(&delivery.data) {
                            println!("Received event: {:?}", event);
                            if predicate(&event) {
                                delivery.ack(BasicAckOptions::default()).await.expect("Failed to ack message");
                                return Some(event);
                            }
                        }
                        delivery.ack(BasicAckOptions::default()).await.expect("Failed to ack message");
                    }
                    Err(e) => {
                        println!("Error receiving message: {:?}", e);
                    }
                }
            }
            None
        } => result,
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum TestEvent {
    #[serde(rename = "test.something")]
    Something { name: String },
}

#[cfg(feature = "mysql")]
pub async fn run_test_with_utils<F, Fut>(
    secret: Option<String>,
    hashing_scheme: Option<HashingScheme>,
    restricted_pattern: Option<String>,
    at_duration_in_seconds: Option<i64>,
    rt_duration_in_seconds: Option<i64>,
    verification_required: Option<bool>,
    vr_duration_in_seconds: Option<i64>,
    test: F,
) where
    F: Fn(
        Arc<Mutex<dyn UserRepository>>,
        Arc<Mutex<dyn RoleRepository>>,
        DatabasePool,
        TestServer,
        Channel,
        Consumer,
        String,
    ) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    from_filename(".env.local").or(dotenv()).ok();
    run_test_with_repo(|user_repository, role_repository, pool| async {
        let id = Uuid::new_v4();
        let exchange_name = format!("nebula.auth.test-{}", id);
        let (channel, consumer, queue_name) = setup_test_consumer(&exchange_name).await;
        let server = create_test_server_v2(
            secret.clone().unwrap_or("secret".to_string()),
            user_repository.clone(),
            role_repository.clone(),
            hashing_scheme.clone().unwrap_or(HashingScheme::BcryptLow),
            restricted_pattern.clone(),
            at_duration_in_seconds.clone().unwrap_or(60),
            rt_duration_in_seconds.clone().unwrap_or(60),
            verification_required.clone().unwrap_or(false),
            vr_duration_in_seconds.clone().unwrap_or(172800),
            exchange_name,
        )
        .await;

        test(
            user_repository,
            role_repository,
            pool,
            server,
            channel,
            consumer,
            queue_name,
        )
        .await;
    })
    .await
}

#[cfg(feature = "mysql")]
async fn run_test_with_repo<F, Fut>(test: F)
where
    F: Fn(Arc<Mutex<dyn UserRepository>>, Arc<Mutex<dyn RoleRepository>>, DatabasePool) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    run_test_with_db_pool(|pool| async {
        let user_repository = create_user_repository(pool.clone());
        let role_repository = create_role_repository(pool.clone());

        test(user_repository, role_repository, pool).await
    })
    .await;
}

#[cfg(feature = "mysql")]
async fn run_test_with_db_pool<F, Fut>(test: F)
where
    F: Fn(DatabasePool) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let db_engine = get_database_engine();
    let (pool, db_url) = create_test_pool(&db_engine).await.unwrap();
    pool.migrate().await;
    test(pool.clone()).await;
    drop_database(&pool, &db_url).await;
}

#[cfg(feature = "mysql")]
async fn create_test_pool(
    database_engine: &DatabaseEngine,
) -> Result<(DatabasePool, String), Error> {
    match database_engine {
        DatabaseEngine::Sqlite => {
            let database_url = get_test_database_url(&get_sqlite_db_url().unwrap());
            Ok((
                DatabasePool::Sqlite(create_sqlite_pool(&database_url).await?),
                database_url,
            ))
        }
        DatabaseEngine::Mysql => {
            let database_url = get_test_database_url(&get_mysql_database_url().unwrap());
            Ok((
                DatabasePool::MySql(create_mysql_pool(&database_url).await?),
                database_url,
            ))
        }
    }
}

#[cfg(feature = "mysql")]
async fn drop_database(database_pool: &DatabasePool, database_url: &str) {
    match database_pool {
        DatabasePool::MySql(_) => {
            MySql::drop_database(database_url).await.unwrap();
        }
        DatabasePool::Sqlite(_) => {
            Sqlite::drop_database(database_url).await.unwrap();
        }
    }
}

#[cfg(feature = "mysql")]
fn get_test_database_url(database_url: &str) -> String {
    format!(
        "{}-{}",
        database_url,
        Uuid::new_v4().to_string().replace("-", "_")
    )
}
