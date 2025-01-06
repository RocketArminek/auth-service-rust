use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::UserDTO;
use crate::utils::runners::{run_message_publisher_test_with_default};

#[tokio::test]
async fn it_dispatches_messages_into_queue() {
    run_message_publisher_test_with_default(
        |c| async move {
            c.message_publisher.lock().await
                .publish(&UserEvents::Created {
                    user: UserDTO {
                        id: uuid::Uuid::new_v4(),
                        email: "some@test.com".to_string(),
                        last_name: None,
                        first_name: None,
                        roles: vec![],
                        avatar_path: None,
                        is_verified: false,
                    },
                })
                .await
                .unwrap();

            let event = c.wait_for_event(5, |_| true).await;

            assert!(event.is_some(), "Should have received some event");

            if let Some(UserEvents::Created { user }) = event {
                assert_eq!(user.email, "some@test.com");
            }
        }
    ).await;
}
