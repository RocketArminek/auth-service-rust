use crate::domain::event::UserEvents;
use crate::infrastructure::message_publisher::MessagePublisher;
use axum::async_trait;
use lapin::options::{BasicPublishOptions, ExchangeDeclareOptions};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind};
use std::env;
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
    ) -> Result<RabbitmqMessagePublisher, Box<dyn Error>> {
        let channel = connection.create_channel().await?;

        channel
            .exchange_declare(
                &exchange_name,
                exchange_kind,
                exchange_declare_options,
                FieldTable::default(),
            )
            .await?;

        Ok(RabbitmqMessagePublisher {
            channel,
            exchange_name,
        })
    }
}

#[async_trait]
impl MessagePublisher for RabbitmqMessagePublisher {
    async fn publish(&self, event: &UserEvents) -> Result<(), Box<dyn Error>> {
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
}

pub async fn create_rabbitmq_connection() -> Connection {
    let rabbitmq_url = env::var("RABBITMQ_URL").unwrap_or("amqp://localhost:5672".to_string());

    Connection::connect(&rabbitmq_url, ConnectionProperties::default())
        .await
        .expect("Failed to connect to rabbitmq")
}

pub async fn create_rabbitmq_message_publisher() -> Arc<Mutex<dyn MessagePublisher + Send + Sync>> {
    tracing::info!("Event driven is turned on");
    let rabbitmq_exchange_name =
        env::var("RABBITMQ_EXCHANGE_NAME").unwrap_or("nebula.auth.events".to_string());
    let conn = create_rabbitmq_connection().await;

    tracing::info!(
        "Rabbitmq publishing method configured: exchange={}",
        &rabbitmq_exchange_name
    );

    let message_publisher = RabbitmqMessagePublisher::new(
        &conn,
        rabbitmq_exchange_name,
        ExchangeKind::Fanout,
        ExchangeDeclareOptions {
            durable: true,
            auto_delete: false,
            ..ExchangeDeclareOptions::default()
        },
    )
    .await
    .expect("Failed to create message publisher");

    Arc::new(Mutex::new(message_publisher))
}
