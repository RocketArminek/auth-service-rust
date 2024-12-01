use crate::domain::event::UserEvents;
use crate::infrastructure::rabbitmq_message_publisher::create_rabbitmq_message_publisher;
use axum::async_trait;
use std::env;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

#[async_trait]
pub trait MessagePublisher {
    async fn publish(&self, event: &UserEvents) -> Result<(), Box<dyn Error>>;
    async fn publish_all(&self, events: Vec<&UserEvents>) -> Result<(), Box<dyn Error>>;
}

#[derive(Clone)]
pub struct NullPublisher {}

#[async_trait]
impl MessagePublisher for NullPublisher {
    async fn publish(&self, _event: &UserEvents) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
    async fn publish_all(&self, _events: Vec<&UserEvents>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

pub async fn create_message_publisher() -> Arc<Mutex<dyn MessagePublisher + Send + Sync>> {
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
