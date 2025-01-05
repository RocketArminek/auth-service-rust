use crate::infrastructure::rabbitmq_message_publisher::create_rabbitmq_message_publisher;
use axum::async_trait;
use serde::Serialize;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::application::message_publisher_configuration::MessagePublisherConfiguration;

#[async_trait]
pub trait MessagePublisher<T: Serialize + Send + Sync>: Send + Sync {
    async fn publish(&self, event: &T) -> Result<(), Box<dyn Error>>;
    async fn publish_all(&self, events: Vec<&T>) -> Result<(), Box<dyn Error>>;
}

#[derive(Clone)]
pub struct NullPublisher {}

#[async_trait]
impl<T: Serialize + Send + Sync> MessagePublisher<T> for NullPublisher {
    async fn publish(&self, _event: &T) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    async fn publish_all(&self, _events: Vec<&T>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

pub async fn create_message_publisher<T: Serialize + Send + Sync + 'static>(
    publisher_config: &MessagePublisherConfiguration,
) -> Arc<Mutex<dyn MessagePublisher<T>>> {
    match publisher_config {
        MessagePublisherConfiguration::Rabbitmq(config) => {
            tracing::info!("Event driven is turned on");
            create_rabbitmq_message_publisher(config).await
        }
        MessagePublisherConfiguration::None => {
            tracing::info!("Event driven is turned off. Events wont be published.");
            Arc::new(Mutex::new(NullPublisher {}))
        }
    }
}
