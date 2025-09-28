use crate::application::configuration::message_publisher::RabbitmqConfiguration;
use crate::infrastructure::message_publisher::MessagePublisher;
use crate::infrastructure::utils::retry_with_backoff;
use async_trait::async_trait;
use lapin::options::{BasicPublishOptions, ExchangeDeclareOptions};
use lapin::types::{FieldTable, ShortString};
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind};
use serde::Serialize;
use std::error::Error;
use std::sync::Arc;

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
                ShortString::from(exchange_name.clone()),
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
                ShortString::from(self.exchange_name.clone()),
                ShortString::from("".to_owned()),
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
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
    retry_with_backoff(
        || async {
            Connection::connect(config.rabbitmq_url(), ConnectionProperties::default()).await
        },
        "Rabbitmq",
        5,
        std::time::Duration::from_millis(500),
        true,
    )
    .await
    .unwrap()
}

pub async fn create_rabbitmq_message_publisher<T: Serialize + Send + Sync + 'static>(
    config: &RabbitmqConfiguration,
    conn: &Connection,
) -> Arc<dyn MessagePublisher<T> + Send + Sync> {
    let message_publisher = RabbitmqMessagePublisher::new(
        &conn,
        config.rabbitmq_exchange_name().to_string(),
        config.rabbitmq_exchange_kind().clone(),
        config.rabbitmq_exchange_declare_options(),
    )
    .await
    .expect("Failed to create message publisher");

    tracing::info!("Rabbitmq message publisher connected");

    Arc::new(message_publisher)
}
