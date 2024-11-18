use std::error::Error;
use axum::async_trait;
use serde::Serialize;

#[async_trait]
pub trait MessagePublisher {
    async fn publish<T>(&self, event: &T) -> Result<(), Box<dyn Error>> where T: Serialize + Send + Sync;
}
