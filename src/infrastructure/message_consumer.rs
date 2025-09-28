use crate::application::configuration::message_publisher::RabbitmqConfiguration;
use crate::infrastructure::rabbitmq_message_publisher::create_rabbitmq_connection;
use async_trait::async_trait;
use futures_lite::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::{FieldTable, ShortString};
use lapin::{Connection, Consumer, ExchangeKind};
use serde::Deserialize;
use std::error::Error;

#[async_trait]
pub trait MessageConsumer: Send + Sync {
    async fn basic_consume<T>(&mut self) -> Option<T>
    where
        T: for<'de> Deserialize<'de> + Send + Sync + 'static;
}

#[derive(Clone)]
pub struct NoneConsumer {}

#[async_trait]
impl MessageConsumer for NoneConsumer {
    async fn basic_consume<T>(&mut self) -> Option<T> {
        None
    }
}

#[derive(Clone)]
pub struct DebugRabbitmqConsumer {
    consumer: Consumer,
}

impl DebugRabbitmqConsumer {
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

        let queue_name = "debug_queue".to_owned();
        channel
            .queue_declare(
                ShortString::from(queue_name.clone()),
                QueueDeclareOptions {
                    exclusive: true,
                    auto_delete: true,
                    ..QueueDeclareOptions::default()
                },
                FieldTable::default(),
            )
            .await?;

        channel
            .queue_bind(
                ShortString::from(queue_name.clone()),
                ShortString::from(exchange_name.clone()),
                ShortString::from("".to_owned()),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;

        let consumer = channel
            .basic_consume(
                ShortString::from(queue_name.clone()),
                ShortString::from("debug_consumer".to_owned()),
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await?;

        Ok(Self { consumer })
    }
}

#[async_trait]
impl MessageConsumer for DebugRabbitmqConsumer {
    async fn basic_consume<T>(&mut self) -> Option<T>
    where
        T: for<'de> Deserialize<'de> + Send + Sync + 'static,
    {
        let delivery = self.consumer.next().await?.ok()?;
        let event = serde_json::from_slice::<T>(&delivery.data).ok()?;
        delivery.ack(BasicAckOptions::default()).await.ok()?;

        Some(event)
    }
}

pub async fn create_debug_rabbitmq_consumer(
    config: &RabbitmqConfiguration,
) -> DebugRabbitmqConsumer {
    let conn = create_rabbitmq_connection(config).await;

    DebugRabbitmqConsumer::new(
        &conn,
        config.rabbitmq_exchange_name().to_string(),
        config.rabbitmq_exchange_kind().clone(),
        config.rabbitmq_exchange_declare_options(),
    )
    .await
    .expect("Should create consumer")
}
