use crate::utils::cli::CommandFactory;
use crate::utils::events::wait_for_event;
use auth_service::domain::event::UserEvents;
use auth_service::domain::repository::{PermissionRepository, RoleRepository, SessionRepository, UserRepository};
use auth_service::infrastructure::message_publisher::MessagePublisher;
use axum_test::TestServer;
use lapin::Consumer;
use std::sync::Arc;

pub struct PublisherTestContext {
    pub message_publisher: Arc<dyn MessagePublisher<UserEvents>>,
    pub consumer: Consumer,
}

impl PublisherTestContext {
    pub fn new(
        message_publisher: Arc<dyn MessagePublisher<UserEvents>>,
        consumer: Consumer,
    ) -> PublisherTestContext {
        PublisherTestContext {
            message_publisher,
            consumer,
        }
    }

    pub async fn wait_for_event<F>(&self, timeout: u64, predicate: F) -> Option<UserEvents>
    where
        F: Fn(&UserEvents) -> bool,
    {
        wait_for_event(self.consumer.clone(), timeout, predicate).await
    }
}

pub struct DatabaseTestContext {
    pub user_repository: Arc<dyn UserRepository>,
    pub role_repository: Arc<dyn RoleRepository>,
    pub session_repository: Arc<dyn SessionRepository>,
    pub permission_repository: Arc<dyn PermissionRepository>,
}

impl DatabaseTestContext {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        role_repository: Arc<dyn RoleRepository>,
        session_repository: Arc<dyn SessionRepository>,
        permission_repository: Arc<dyn PermissionRepository>,
    ) -> DatabaseTestContext {
        DatabaseTestContext {
            user_repository,
            role_repository,
            session_repository,
            permission_repository,
        }
    }
}

pub struct AcceptanceTestContext {
    pub user_repository: Arc<dyn UserRepository>,
    pub role_repository: Arc<dyn RoleRepository>,
    pub session_repository: Arc<dyn SessionRepository>,
    pub server: TestServer,
    pub consumer: Consumer,
}

impl AcceptanceTestContext {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        role_repository: Arc<dyn RoleRepository>,
        session_repository: Arc<dyn SessionRepository>,
        server: TestServer,
        consumer: Consumer,
    ) -> Self {
        AcceptanceTestContext {
            user_repository,
            role_repository,
            session_repository,
            server,
            consumer,
        }
    }

    pub async fn wait_for_event<F>(&self, timeout: u64, predicate: F) -> Option<UserEvents>
    where
        F: Fn(&UserEvents) -> bool,
    {
        wait_for_event(self.consumer.clone(), timeout, predicate).await
    }
}

pub struct CliTestContext {
    pub user_repository: Arc<dyn UserRepository>,
    pub role_repository: Arc<dyn RoleRepository>,
    pub cf: CommandFactory,
}

impl CliTestContext {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        role_repository: Arc<dyn RoleRepository>,
        cf: CommandFactory,
    ) -> Self {
        CliTestContext {
            user_repository,
            role_repository,
            cf,
        }
    }
}
