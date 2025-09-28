use crate::utils::runners::run_message_publisher_test_with_default;
use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::UserDTO;

#[tokio::test]
async fn it_dispatches_message_into_queue() {
    run_message_publisher_test_with_default(|mut c| async move {
        c.message_publisher
            .publish(&UserEvents::Created {
                user: UserDTO {
                    id: uuid::Uuid::new_v4(),
                    email: "some@test.com".to_string(),
                    last_name: None,
                    first_name: None,
                    roles: vec![],
                    permissions: Default::default(),
                    avatar_path: None,
                    is_verified: false,
                },
            })
            .await
            .unwrap();

        c.tester
            .assert_event_published(
                |e| match e {
                    Some(UserEvents::Created { user }) => {
                        assert_eq!(user.email, "some@test.com");
                    }
                    _ => panic!("Got {:?}", e),
                },
                5,
            )
            .await;
    })
    .await;
}

#[tokio::test]
async fn it_dispatches_all_messages_into_queue() {
    run_message_publisher_test_with_default(|mut c| async move {
        c.message_publisher
            .publish_all(vec![
                &UserEvents::Created {
                    user: UserDTO {
                        id: uuid::Uuid::new_v4(),
                        email: "some@test.com".to_string(),
                        last_name: None,
                        first_name: None,
                        roles: vec![],
                        permissions: Default::default(),
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
                        permissions: Default::default(),
                        avatar_path: None,
                        is_verified: true,
                    },
                },
            ])
            .await
            .unwrap();

        c.tester
            .assert_event_published(
                |e| match e {
                    Some(UserEvents::Created { user }) => {
                        assert_eq!(user.email, "some@test.com");
                        assert!(!user.is_verified, "It should not be verified");
                    }
                    _ => panic!("Got {:?}", e),
                },
                5,
            )
            .await;

        c.tester
            .assert_event_published(
                |e| match e {
                    Some(UserEvents::Verified { user }) => {
                        assert_eq!(user.email, "some@test.com");
                        assert!(user.is_verified, "It should be verified");
                    }
                    _ => panic!("Got {:?}", e),
                },
                5,
            )
            .await;
    })
    .await;
}
