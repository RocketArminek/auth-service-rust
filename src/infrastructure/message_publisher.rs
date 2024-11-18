use std::error::Error;
use axum::async_trait;
use serde::Serialize;

#[async_trait]
pub trait MessagePublisher {
    async fn publish<T>(&self, event: &T) -> Result<(), Box<dyn Error>> where T: Serialize + Send + Sync;
}

#[derive(Clone)]
pub struct NullPublisher {}

#[async_trait]
impl MessagePublisher for NullPublisher {
    async fn publish<T>(&self, _event: &T) -> Result<(), Box<dyn Error>> where T: Serialize + Send + Sync {
        Ok(())
    }
}
