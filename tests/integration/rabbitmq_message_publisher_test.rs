use std::env;
use lapin::{Connection, ConnectionProperties, ExchangeKind};
use lapin::options::ExchangeDeclareOptions;
use auth_service::infrastructure::message_publisher::MessagePublisher;
use auth_service::infrastructure::rabbitmq_message_publisher::RabbitmqMessagePublisher;
use crate::utils;
use crate::utils::TestEvent;

#[tokio::test]
async fn it_dispatches_messages_into_queue() {
    let rabbitmq_url = env::var("RABBITMQ_URL").unwrap_or("amqp://127.0.0.1:5672".to_string());
    let exchange_name = "nebula.auth.test";
    let (_channel, consumer, _queue_name) = utils::setup_test_consumer(exchange_name).await;
    let connection = Connection::connect(
        &rabbitmq_url,
        ConnectionProperties::default()
    ).await.unwrap();
    let message_publisher = RabbitmqMessagePublisher::new(
        &connection,
        exchange_name.to_string(),
        ExchangeKind::Fanout,
        ExchangeDeclareOptions {
            durable: false,
            auto_delete: true,
            ..ExchangeDeclareOptions::default()
        }
    ).await.unwrap();

    message_publisher.publish(
        &TestEvent::Something { name: String::from("some") }
    ).await.unwrap();

    let event = utils::wait_for_event::<TestEvent>(
        consumer,
        5,
        |_| true,
    ).await;

    assert!(event.is_some(), "Should have received some event");

    if let Some(TestEvent::Something { name }) = event {
        assert_eq!(name, "some");
    }
}
