use crate::infrastructure::rabbitmq_message_publisher::create_rabbitmq_message_publisher;
use axum::async_trait;
use serde::Serialize;
use std::env;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

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
) -> Arc<Mutex<dyn MessagePublisher<T> + Send + Sync>> {
    let event_driven = env::var("EVENT_DRIVEN")
        .unwrap_or("true".to_string())
        .parse::<bool>()
        .expect("EVENT_DRIVEN must be a boolean");

    if !event_driven {
        tracing::info!("Event driven is turned off. Events wont be published.");

        return Arc::new(Mutex::new(NullPublisher {}));
    }

    create_rabbitmq_message_publisher().await
}
