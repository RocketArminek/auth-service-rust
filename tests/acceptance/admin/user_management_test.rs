use crate::acceptance::utils;
use crate::utils::runners::run_integration_test_with_default;
use auth_service::api::dto::UserListResponse;
use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::UserDTO;
use auth_service::domain::user::User;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn it_creates_restricted_user() {
    run_integration_test_with_default(|mut c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let email = String::from("jon@snow.test");

        let response = c
            .server
            .post("/v1/restricted/users")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
                "role": "ADMIN_USER",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::CREATED);

        c.tester.assert_event_published(|event| {
            match event {
                Some(UserEvents::Created { user }) => {
                    assert_eq!(user.email, email);
                    assert_eq!(user.avatar_path, None);
                    assert_eq!(user.roles, vec!["ADMIN_USER".to_string()]);
                    assert!(user.is_verified);
                }
                _ => panic!("Got {:?}", event),
            }
        }, 5).await;
    })
    .await;
}

#[tokio::test]
async fn it_cannot_create_restricted_user_if_not_permitted() {
    run_integration_test_with_default(|mut c| async move {
        let (_, token) = utils::i_am_logged_in_as_user(&c).await;

        let email = String::from("jon@snow.test");

        let response = c
            .server
            .post("/v1/restricted/users")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
                "role": "ADMIN_USER",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

        c.tester.assert_no_event_published(1).await;
    })
    .await;
}

#[tokio::test]
async fn it_can_list_all_user_as_an_privileged_role() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let response = c
            .server
            .get("/v1/restricted/users?page=1&limit=10")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<UserListResponse>();

        assert_eq!(body.items.len(), 1);
        assert_eq!(body.items[0].email, "admin@test.com");
        assert_eq!(body.limit, 10);
        assert_eq!(body.page, 1);
        assert_eq!(body.total, 1);
        assert_eq!(body.pages, 1);
    })
    .await;
}

#[tokio::test]
async fn it_can_list_all_user_with_roles() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let response = c
            .server
            .get("/v1/restricted/users?page=1&limit=10")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<UserListResponse>();

        assert_eq!(body.items.len(), 1);
        assert_eq!(body.items[0].email, "admin@test.com");
        assert!(!body.items[0].roles.is_empty());
        assert_eq!(body.limit, 10);
        assert_eq!(body.page, 1);
        assert_eq!(body.total, 1);
        assert_eq!(body.pages, 1);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_single_user() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let user = User::now_with_email_and_password(
            String::from("user@test.com"),
            String::from("User#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .get(&format!("/v1/restricted/users/{}", user.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<UserDTO>();
        assert_eq!(body.email, "user@test.com");
    })
    .await;
}

#[tokio::test]
async fn it_can_delete_user() {
    run_integration_test_with_default(|mut c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let user = User::now_with_email_and_password(
            String::from("user@test.com"),
            String::from("User#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .delete(&format!("/v1/restricted/users/{}", user.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let deleted_user = c.user_repository.get_by_id(&user.id).await;
        assert!(deleted_user.is_err());

        c.tester.assert_event_published(|event| {
            match event {
                Some(UserEvents::Deleted { user }) => {
                    assert_eq!(user.email, "user@test.com".to_string());
                    assert_eq!(user.first_name.unwrap(), "Jon".to_string());
                    assert_eq!(user.last_name.unwrap(), "Snow".to_string());
                    assert_eq!(user.avatar_path, None);
                    assert!(user.roles.is_empty());
                }
                _ => panic!("Got {:?}", event),
            }
        }, 5).await;
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_for_nonexistent_user() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let non_existent_id = Uuid::new_v4();
        let response = c
            .server
            .get(&format!("/v1/restricted/users/{}", non_existent_id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn it_updates_other_user_information() {
    run_integration_test_with_default(|mut c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let user = User::now_with_email_and_password(
            String::from("user@test.com"),
            String::from("User#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .put(&format!("/v1/restricted/users/{}", user.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .json(&json!({
                "firstName": "Jon",
                "lastName": "Doe",
                "avatarPath": "https://somepath.com/123.jpg",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let body = response.json::<UserDTO>();
        assert_eq!(body.first_name.unwrap(), "Jon");
        assert_eq!(body.last_name.unwrap(), "Doe");
        assert_eq!(body.avatar_path.unwrap(), "https://somepath.com/123.jpg");

        c.tester.assert_event_published(|event| {
            match event {
                Some(UserEvents::Updated { old_user, new_user }) => {
                    assert_eq!(old_user.first_name, Some("Jon".to_string()));
                    assert_eq!(old_user.last_name, Some("Snow".to_string()));
                    assert_eq!(old_user.avatar_path, None);
                    assert!(old_user.roles.is_empty());

                    assert_eq!(new_user.email, "user@test.com".to_string());
                    assert_eq!(new_user.first_name.unwrap(), "Jon".to_string());
                    assert_eq!(new_user.last_name.unwrap(), "Doe".to_string());
                    assert_eq!(
                        new_user.avatar_path,
                        Some("https://somepath.com/123.jpg".to_string())
                    );
                    assert!(new_user.roles.is_empty());
                }
                _ => panic!("Got {:?}", event),
            }
        }, 5).await;
    })
    .await;
}

#[tokio::test]
async fn it_cannot_update_none_existing_user() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::i_am_logged_in_as_admin(&c).await;

        let response = c
            .server
            .put(&format!("/v1/restricted/users/{}", Uuid::new_v4()))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .json(&json!({
                "email": "test@wp.pl",
                "firstName": "Jon",
                "lastName": "Doe",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    })
    .await;
}
