use std::sync::Arc;
use axum_test::TestServer;
use lapin::Consumer;
use tokio::sync::Mutex;
use auth_service::domain::event::UserEvents;
use auth_service::domain::repositories::{RoleRepository, UserRepository};
use crate::utils::events::wait_for_event;

pub struct IntegrationTestContext {
    pub user_repository: Arc<Mutex<dyn UserRepository>>,
    pub role_repository: Arc<Mutex<dyn RoleRepository>>,
    pub server: TestServer,
    pub consumer: Consumer,
}

impl IntegrationTestContext {
    pub fn new(
        user_repository: Arc<Mutex<dyn UserRepository>>,
        role_repository: Arc<Mutex<dyn RoleRepository>>,
        server: TestServer,
        consumer: Consumer,
    ) -> Self {
        IntegrationTestContext {
            user_repository,
            role_repository,
            server,
            consumer,
        }
    }

    pub async fn wait_for_event<F>(&self, timeout: u64, predicate: F) -> Option<UserEvents>
    where
        F: Fn(&UserEvents) -> bool
    {
        wait_for_event(self.consumer.clone(), timeout, predicate).await
    }
}
