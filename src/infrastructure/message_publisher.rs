use crate::application::configuration::messaging::MessagingConfiguration;
use crate::infrastructure::rabbitmq_message_publisher::{
    create_rabbitmq_connection, create_rabbitmq_message_publisher,
};
use async_trait::async_trait;
use serde::Serialize;
use std::error::Error;
use std::fmt::Display;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub enum MessagingEngine {
    Rabbitmq,
    #[default]
    None,
}

impl Display for MessagingEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessagingEngine::None => write!(f, "none"),
            MessagingEngine::Rabbitmq => write!(f, "rabbitmq"),
        }
    }
}

impl From<MessagingEngine> for String {
    fn from(value: MessagingEngine) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for MessagingEngine {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "none" => Ok(MessagingEngine::None),
            "rabbitmq" => Ok(MessagingEngine::Rabbitmq),
            _ => Err(format!("Unknown message publisher type: {}", value)),
        }
    }
}

#[async_trait]
pub trait MessagePublisher<T: Serialize + Send + Sync>: Send + Sync {
    async fn publish(&self, event: &T) -> Result<(), Box<dyn Error>>;
    async fn publish_all(&self, events: Vec<&T>) -> Result<(), Box<dyn Error>>;
}

#[derive(Clone)]
pub struct NonePublisher {}

#[async_trait]
impl<T: Serialize + Send + Sync> MessagePublisher<T> for NonePublisher {
    async fn publish(&self, _event: &T) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    async fn publish_all(&self, _events: Vec<&T>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

pub async fn create_message_publisher<T: Serialize + Send + Sync + 'static>(
    publisher_config: &MessagingConfiguration,
) -> Arc<dyn MessagePublisher<T>> {
    match publisher_config {
        MessagingConfiguration::Rabbitmq(config) => {
            let conn = create_rabbitmq_connection(config).await;

            create_rabbitmq_message_publisher(config, &conn).await
        }
        MessagingConfiguration::None => {
            tracing::info!("Event driven is turned off. Events wont be published.");
            Arc::new(NonePublisher {})
        }
    }
}
