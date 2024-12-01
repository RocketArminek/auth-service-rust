use auth_service::api::routes::routes;
use auth_service::api::server_state::{parse_restricted_pattern, ServerState};
use auth_service::domain::crypto::HashingScheme;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use auth_service::infrastructure::rabbitmq_message_publisher::RabbitmqMessagePublisher;
use axum_test::TestServer;
use futures_lite::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties, Consumer, ExchangeKind};
use serde::{Deserialize, Serialize};
use sqlx::{MySql, Pool};
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

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
