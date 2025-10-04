use crate::utils::cli::CommandFactory;
use auth_service::domain::event::UserEvents;
use auth_service::domain::repository::{PermissionRepository, RoleRepository, UserRepository};
use auth_service::infrastructure::message_consumer::MessageConsumer;
use auth_service::infrastructure::message_publisher::MessagePublisher;
use axum_test::TestServer;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

pub struct PublisherTestContext {
    pub message_publisher: MessagePublisher,
    pub tester: MessagingTester,
}

impl PublisherTestContext {
    pub fn new(
        message_publisher: MessagePublisher,
        tester: MessagingTester,
    ) -> PublisherTestContext {
        PublisherTestContext {
            message_publisher,
            tester,
        }
    }
}

pub struct DatabaseTestContext {
    pub user_repository: Arc<dyn UserRepository>,
    pub role_repository: Arc<dyn RoleRepository>,
    pub permission_repository: Arc<dyn PermissionRepository>,
}

impl DatabaseTestContext {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        role_repository: Arc<dyn RoleRepository>,
        permission_repository: Arc<dyn PermissionRepository>,
    ) -> DatabaseTestContext {
        DatabaseTestContext {
            user_repository,
            role_repository,
            permission_repository,
        }
    }
}

pub struct AcceptanceTestContext {
    pub user_repository: Arc<dyn UserRepository>,
    pub role_repository: Arc<dyn RoleRepository>,
    pub permission_repository: Arc<dyn PermissionRepository>,
    pub server: TestServer,
    pub tester: MessagingTester,
}

impl AcceptanceTestContext {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        role_repository: Arc<dyn RoleRepository>,
        permission_repository: Arc<dyn PermissionRepository>,
        server: TestServer,
        tester: MessagingTester,
    ) -> Self {
        AcceptanceTestContext {
            user_repository,
            role_repository,
            permission_repository,
            server,
            tester,
        }
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

pub struct MessagingTester {
    pub consumer: MessageConsumer,
}

impl MessagingTester {
    pub fn new(consumer: MessageConsumer) -> Self {
        Self { consumer }
    }

    pub async fn assert_event_published<F>(&mut self, predicate: F, timeout_secs: u64)
    where
        F: Fn(Option<UserEvents>),
    {
        let timeout_duration = Duration::from_secs(timeout_secs);

        match &self.consumer {
            MessageConsumer::None => {}
            MessageConsumer::DebugRabbitmqConsumer(_) => {
                match timeout(
                    timeout_duration,
                    self.consumer.basic_consume::<UserEvents>(),
                )
                .await
                {
                    Ok(event) => predicate(event),
                    Err(_) => panic!("Event assertion timed out after {} seconds", timeout_secs),
                }
            }
        }
    }

    pub async fn assert_no_event_published(&mut self, timeout_secs: u64) {
        let timeout_duration = Duration::from_secs(timeout_secs);

        match &self.consumer {
            MessageConsumer::None => {}
            MessageConsumer::DebugRabbitmqConsumer(_) => {
                match timeout(
                    timeout_duration,
                    self.consumer.basic_consume::<UserEvents>(),
                )
                .await
                {
                    Ok(event) => {
                        panic!("Expected no event, but received: {:?}", event);
                    }
                    Err(_) => {}
                }
            }
        }
    }
}
