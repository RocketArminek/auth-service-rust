use lapin::BasicProperties;
use lapin::options::BasicPublishOptions;
use serde::{Deserialize, Serialize};
use crate::utils;

#[tokio::test]
async fn it_dispatches_message_into_queue() {
    let exchange_name = "nebula.auth.test";
    let (channel, consumer, _queue_name) = utils::setup_test_consumer(exchange_name)
        .await;

    let event = TestEvent::Something { name: String::from("some") };
    let payload = serde_json::to_vec(&event).unwrap();

    channel
        .basic_publish(
            exchange_name,
            "",
            BasicPublishOptions::default(),
            &payload,
            BasicProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2),
        )
        .await
        .expect("publish failed");

    let event = utils::wait_for_event::<TestEvent>(
        consumer,
        5,
        |event| matches!(event, TestEvent::Something { .. }),
    )
        .await;

    assert!(event.is_some(), "Should have received some event");

    if let Some(TestEvent::Something { name }) = event {
        assert_eq!(name, "some");
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum TestEvent {
    #[serde(rename = "test.something")]
    Something {
        name: String
    },
}
