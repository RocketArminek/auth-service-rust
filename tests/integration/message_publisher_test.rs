use crate::utils::runners::run_message_publisher_test_with_default;
use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::UserDTO;

#[tokio::test]
async fn it_dispatches_message_into_queue() {
    run_message_publisher_test_with_default(|c| async move {
        c.message_publisher
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
    })
    .await;
}

#[tokio::test]
async fn it_dispatches_all_messages_into_queue() {
    run_message_publisher_test_with_default(|c| async move {
        c.message_publisher
            .publish_all(vec![
                &UserEvents::Created {
                    user: UserDTO {
                        id: uuid::Uuid::new_v4(),
                        email: "some@test.com".to_string(),
                        last_name: None,
                        first_name: None,
                        roles: vec![],
                        avatar_path: None,
                        is_verified: false,
                    },
                },
                &UserEvents::Verified {
                    user: UserDTO {
                        id: uuid::Uuid::new_v4(),
                        email: "some@test.com".to_string(),
                        last_name: None,
                        first_name: None,
                        roles: vec![],
                        avatar_path: None,
                        is_verified: true,
                    },
                },
            ])
            .await
            .unwrap();

        let created = c
            .wait_for_event(5, |e| matches!(e, UserEvents::Created { .. }))
            .await;

        assert!(created.is_some(), "Should have received created event");

        let verified = c
            .wait_for_event(5, |e| matches!(e, UserEvents::Verified { .. }))
            .await;

        assert!(verified.is_some(), "Should have received verified event");

        if let Some(UserEvents::Created { user }) = created {
            assert_eq!(user.email, "some@test.com");
            assert!(!user.is_verified, "It should not be verified");
        }

        if let Some(UserEvents::Verified { user }) = verified {
            assert_eq!(user.email, "some@test.com");
            assert!(user.is_verified, "It should be verified");
        }
    })
    .await;
}
