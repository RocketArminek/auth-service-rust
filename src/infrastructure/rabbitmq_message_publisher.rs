use lapin::{BasicProperties, Channel, Connection, ExchangeKind};
use lapin::options::{BasicPublishOptions, ExchangeDeclareOptions};
use std::error::Error;
use lapin::types::FieldTable;
use axum::async_trait;
use serde::Serialize;
use crate::infrastructure::message_publisher::MessagePublisher;

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

        channel.exchange_declare(
            &exchange_name,
            exchange_kind,
            exchange_declare_options,
            FieldTable::default(),
        ).await?;

        Ok(RabbitmqMessagePublisher { channel, exchange_name })
    }
}

#[async_trait]
impl MessagePublisher for RabbitmqMessagePublisher {
    async fn publish<T>(&self, event: &T) -> Result<(), Box<dyn Error>>
    where
        T: Serialize + Send + Sync
    {
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
