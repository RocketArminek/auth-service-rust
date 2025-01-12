use crate::application::message_publisher_configuration::RabbitmqConfiguration;
use crate::infrastructure::message_publisher::MessagePublisher;
use async_trait::async_trait;
use lapin::options::{BasicPublishOptions, ExchangeDeclareOptions};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind};
use serde::Serialize;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RabbitmqMessagePublisher {
    channel: Channel,
    exchange_name: String,
}

impl RabbitmqMessagePublisher {
    pub async fn new(
        connection: &Connection,
        exchange_name: String,
        exchange_kind: ExchangeKind,
        exchange_declare_options: ExchangeDeclareOptions,
    ) -> Result<Self, Box<dyn Error>> {
        let channel = connection.create_channel().await?;

        channel
            .exchange_declare(
                &exchange_name,
                exchange_kind,
                exchange_declare_options,
                FieldTable::default(),
            )
            .await?;

        Ok(Self {
            channel,
            exchange_name,
        })
    }
}

#[async_trait]
impl<T: Serialize + Send + Sync> MessagePublisher<T> for RabbitmqMessagePublisher {
    async fn publish(&self, event: &T) -> Result<(), Box<dyn Error>> {
        let payload = serde_json::to_vec(event)?;

        self.channel
            .basic_publish(
                &self.exchange_name,
                "",
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2), // persistent delivery
            )
            .await?
            .await?;

        Ok(())
    }

    async fn publish_all(&self, events: Vec<&T>) -> Result<(), Box<dyn Error>> {
        for event in events {
            self.publish(event).await?;
        }

        Ok(())
    }
}

pub async fn create_rabbitmq_connection(config: &RabbitmqConfiguration) -> Connection {
    let mut retry_count = 0;
    let max_retries = 5;
    let retry_delay = std::time::Duration::from_secs(5);

    loop {
        match Connection::connect(config.rabbitmq_url(), ConnectionProperties::default()).await {
            Ok(connection) => {
                if retry_count > 0 {
                    tracing::info!(
                        "Successfully connected to RabbitMQ after {} retries",
                        retry_count
                    );
                }
                return connection;
            }
            Err(err) => {
                retry_count += 1;
                if retry_count >= max_retries {
                    tracing::error!(
                        "Failed to connect to RabbitMQ after {} attempts: {}",
                        max_retries,
                        err
                    );
                    panic!(
                        "Failed to connect to RabbitMQ after {} attempts",
                        max_retries
                    );
                }
                tracing::warn!(
                    "Failed to connect to RabbitMQ (attempt {}/{}): {}",
                    retry_count,
                    max_retries,
                    err
                );
                tokio::time::sleep(retry_delay).await;
            }
        }
    }
}

pub async fn create_rabbitmq_message_publisher<T: Serialize + Send + Sync + 'static>(
    config: &RabbitmqConfiguration,
) -> Arc<Mutex<dyn MessagePublisher<T> + Send + Sync>> {
    let conn = create_rabbitmq_connection(config).await;

    let message_publisher = RabbitmqMessagePublisher::new(
        &conn,
        config.rabbitmq_exchange_name().to_string(),
        config.rabbitmq_exchange_kind().clone(),
        config.rabbitmq_exchange_declare_options(),
    )
    .await
    .expect("Failed to create message publisher");

    Arc::new(Mutex::new(message_publisher))
}
