use crate::utils;
use crate::utils::TestEvent;
use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::UserDTO;
use auth_service::infrastructure::message_publisher::{MessagePublisher, NullPublisher};
use auth_service::infrastructure::rabbitmq_message_publisher::RabbitmqMessagePublisher;
use lapin::options::ExchangeDeclareOptions;
use lapin::{Connection, ConnectionProperties, ExchangeKind};
use std::env;

#[tokio::test]
async fn it_dispatches_messages_into_queue() {
    let rabbitmq_url = env::var("RABBITMQ_URL").unwrap_or("amqp://127.0.0.1:5672".to_string());
    let id = uuid::Uuid::new_v4();
    let exchange_name = format!("nebula.auth.test-{}", id);
    let (_channel, consumer, _queue_name) = utils::setup_test_consumer(&exchange_name).await;
    let connection = Connection::connect(&rabbitmq_url, ConnectionProperties::default())
        .await
        .unwrap();
    let message_publisher = RabbitmqMessagePublisher::new(
        &connection,
        exchange_name,
        ExchangeKind::Fanout,
        ExchangeDeclareOptions {
            durable: false,
            auto_delete: true,
            ..ExchangeDeclareOptions::default()
        },
    )
    .await
    .unwrap();

    message_publisher
        .publish(&UserEvents::Created {
            user: UserDTO {
                id: uuid::Uuid::new_v4(),
                email: "some@test.com".to_string(),
                last_name: None,
                first_name: None,
                roles: vec![],
                avatar_path: None,
            },
        })
        .await
        .unwrap();

    let event = utils::wait_for_event::<UserEvents>(consumer, 5, |_| true).await;

    assert!(event.is_some(), "Should have received some event");

    if let Some(UserEvents::Created { user }) = event {
        assert_eq!(user.email, "some@test.com");
    }
}

#[tokio::test]
async fn it_does_nothing() {
    let id = uuid::Uuid::new_v4();
    let exchange_name = format!("nebula.auth.test-{}", id);
    let (_channel, consumer, _queue_name) = utils::setup_test_consumer(&exchange_name).await;
    let message_publisher = NullPublisher {};

    message_publisher
        .publish(&UserEvents::Created {
            user: UserDTO {
                id: uuid::Uuid::new_v4(),
                email: "some@test.com".to_string(),
                last_name: None,
                first_name: None,
                roles: vec![],
                avatar_path: None,
            },
        })
        .await
        .unwrap();

    let event = utils::wait_for_event::<TestEvent>(consumer, 5, |_| true).await;

    assert!(event.is_none(), "Should not receive any message");
}
