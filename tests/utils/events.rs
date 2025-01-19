use auth_service::application::configuration::message_publisher::MessagePublisherConfiguration;
use futures_lite::StreamExt;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, QueueBindOptions, QueueDeclareOptions};
use lapin::types::FieldTable;
use lapin::{Channel, Connection, ConnectionProperties, Consumer};
use std::fmt::Debug;
use std::time::Duration;
use tokio::time::sleep;

pub async fn wait_for_event<T: Debug>(
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
