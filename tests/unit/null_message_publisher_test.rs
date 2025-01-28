use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::UserDTO;
use auth_service::infrastructure::message_publisher::{MessagePublisher, NullPublisher};
use uuid::Uuid;

#[tokio::test]
async fn it_does_nothing() {
    let publisher = NullPublisher {};

    let r = publisher
        .publish(&UserEvents::Created {
            user: UserDTO {
                email: "".to_string(),
                id: Uuid::new_v4(),
                roles: vec![],
                permissions: Default::default(),
                is_verified: true,
                last_name: None,
                first_name: None,
                avatar_path: None,
            },
        })
        .await;

    assert!(r.is_ok());
}

#[tokio::test]
async fn it_does_nothing_multiple_times() {
    let publisher = NullPublisher {};
    let r = publisher
        .publish_all(vec![&UserEvents::Created {
            user: UserDTO {
                email: "".to_string(),
                id: Uuid::new_v4(),
                roles: vec![],
                permissions: Default::default(),
                is_verified: true,
                last_name: None,
                first_name: None,
                avatar_path: None,
            },
        }])
        .await;

    assert!(r.is_ok());
}
