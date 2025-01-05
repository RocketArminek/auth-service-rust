use auth_service::domain::repositories::{RoleRepository, UserRepository};
use auth_service::infrastructure::database::{create_pool, DatabasePool};
use auth_service::infrastructure::repository::{create_role_repository, create_user_repository};
use futures_lite::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties, Consumer};
use serde::{Deserialize, Serialize};
use sqlx::migrate::MigrateDatabase;
use sqlx::{Sqlite};
use std::time::Duration;
use tokio::time::sleep;
use auth_service::api::routes::routes;
use auth_service::api::server_state::ServerState;
use axum_test::TestServer;
use sqlx::{MySql};
use std::sync::Arc;
use dotenv::{dotenv, from_filename};
use auth_service::infrastructure::message_publisher::{create_message_publisher, MessagePublisher};
use tokio::sync::Mutex;
use uuid::Uuid;
use auth_service::application::app_configuration::{AppConfiguration, AppConfigurationBuilder};
use auth_service::application::configuration::Configuration;
use auth_service::application::database_configuration::{DatabaseConfiguration, DatabaseConfigurationBuilder};
use auth_service::application::message_publisher_configuration::{MessagePublisherConfiguration, MessagePublisherConfigurationBuilder};
use auth_service::domain::event::UserEvents;

pub async fn create_test_server(
    config: &Configuration,
    user_repository: Arc<Mutex<dyn UserRepository>>,
    role_repository: Arc<Mutex<dyn RoleRepository>>,
    message_publisher: Arc<Mutex<dyn MessagePublisher<UserEvents>>>,
) -> TestServer {
    let config = config.app().clone();

    let state = ServerState::new(
        config,
        user_repository,
        role_repository,
        message_publisher,
    );

    TestServer::new(routes(state)).unwrap()
}

pub async fn setup_test_consumer(
    config: &MessagePublisherConfiguration,
) -> (Channel, Consumer, String) {
    match config {
        MessagePublisherConfiguration::Rabbitmq(config) => {
            let conn = Connection::connect(
                config.rabbitmq_url(),
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
                    config.rabbitmq_exchange_name(),
                    config.rabbitmq_exchange_kind().clone(),
                    config.rabbitmq_exchange_declare_options(),
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
                    config.rabbitmq_exchange_name(),
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
        MessagePublisherConfiguration::None => {
            panic!("Cannot setup test consumer for none message publisher")
        }
    }
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

pub async fn run_test_with_utils<F, Fut, N>(configurator: N, test: F)
where
    F: Fn(
        Arc<Mutex<dyn UserRepository>>,
        Arc<Mutex<dyn RoleRepository>>,
        TestServer,
        Channel,
        Consumer,
        String,
    ) -> Fut,
    Fut: std::future::Future<Output = ()>,
    N: FnOnce(
        &mut AppConfigurationBuilder,
        &mut DatabaseConfigurationBuilder,
        &mut MessagePublisherConfigurationBuilder
    ),
{
    from_filename(".env.test").or(dotenv()).ok();
    let case = Uuid::new_v4().to_string().replace("-", "_");

    let mut app = AppConfigurationBuilder::new();
    app.load_env();
    let mut db = DatabaseConfigurationBuilder::new();
    db.load_env();
    db.database_url(format!("{}_{}", db.database_url.clone().unwrap(), &case));
    let mut publisher = MessagePublisherConfigurationBuilder::new();
    publisher.load_env();
    publisher.rabbitmq_exchange_name(
        format!("{}_{}", publisher.rabbitmq_exchange_name.clone().unwrap(), &case)
    );

    configurator(&mut app, &mut db, &mut publisher);

    let config = Configuration::new(app.build(), db.build(), publisher.build());

    let pool = create_pool(config.db()).await.unwrap();
    pool.migrate().await;
    let user_repository = create_user_repository(pool.clone());
    let role_repository = create_role_repository(pool.clone());

    let message_publisher = create_message_publisher(config.publisher()).await;
    let (channel, consumer, queue_name) = setup_test_consumer(config.publisher()).await;

    let server = create_test_server(
        &config,
        user_repository.clone(),
        role_repository.clone(),
        message_publisher
    ).await;

    test(
        user_repository,
        role_repository,
        server,
        channel,
        consumer,
        queue_name,
    )
    .await;

    drop_database(&pool, config.db().database_url()).await;
}

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
