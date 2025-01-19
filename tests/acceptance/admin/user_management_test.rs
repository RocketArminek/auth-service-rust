use crate::utils::runners::run_integration_test_with_default;
use auth_service::api::dto::{LoginResponse, UserListResponse};
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::UserDTO;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn it_creates_restricted_user() {
    run_integration_test_with_default(|c| async move {
        let mut admin = User::now_with_email_and_password(
            String::from("ned@stark.test"),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("ADMIN_USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        admin.add_role(role.clone());
        c.user_repository.save(&admin).await.unwrap();

        let email = String::from("jon@snow.test");

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "ned@stark.test",
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .post("/v1/restricted/users")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
                "role": "ADMIN_USER",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::CREATED);

        let event = c
            .wait_for_event(5, |event| matches!(event, UserEvents::Created { .. }))
            .await;

        assert!(event.is_some(), "Should have received some event");

        if let Some(UserEvents::Created { user }) = event {
            assert_eq!(user.email, email);
            assert_eq!(user.avatar_path, None);
            assert_eq!(user.roles, vec!["ADMIN_USER".to_string()]);
            assert_eq!(user.is_verified, true);
        }
    })
    .await;
}

#[tokio::test]
async fn it_cannot_create_restricted_user_if_not_permitted() {
    run_integration_test_with_default(|c| async move {
        let mut admin = User::now_with_email_and_password(
            String::from("ned@stark.test"),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        c.user_repository.save(&admin).await.unwrap();

        let email = String::from("jon@snow.test");

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "ned@stark.test",
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .post("/v1/restricted/users")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
                "role": "ADMIN_USER",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

        let event = c.wait_for_event(5, |_| true).await;
        assert!(event.is_none(), "Should not receive any message");
    })
    .await;
}

#[tokio::test]
async fn it_can_list_all_user_as_an_privileged_role() {
    run_integration_test_with_default(|c| async move {
        let mut admin = User::now_with_email_and_password(
            String::from("ned@stark.test"),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("ADMIN_USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        admin.add_role(role.clone());
        c.user_repository.save(&admin).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "ned@stark.test",
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .get("/v1/restricted/users?page=1&limit=10")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<UserListResponse>();

        assert_eq!(body.items.len(), 1);
        assert_eq!(body.items[0].email, "ned@stark.test");
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
        let mut admin = User::now_with_email_and_password(
            String::from("ned@stark.test"),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("ADMIN_USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        admin.add_role(role.clone());
        c.user_repository.save(&admin).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "ned@stark.test",
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .get("/v1/restricted/users?page=1&limit=10")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<UserListResponse>();

        assert_eq!(body.items.len(), 1);
        assert_eq!(body.items[0].email, "ned@stark.test");
        assert_eq!(body.items[0].roles.is_empty(), false);
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
        let mut admin = User::now_with_email_and_password(
            String::from("admin@test.com"),
            String::from("Admin#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("ADMIN_USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        admin.add_role(role.clone());
        c.user_repository.save(&admin).await.unwrap();

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
            .post("/v1/login")
            .json(&json!({
                "email": "admin@test.com",
                "password": "Admin#pass1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .get(&format!("/v1/restricted/users/{}", user.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
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
    run_integration_test_with_default(|c| async move {
        let mut admin = User::now_with_email_and_password(
            String::from("admin@test.com"),
            String::from("Admin#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("ADMIN_USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        admin.add_role(role.clone());
        c.user_repository.save(&admin).await.unwrap();

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
            .post("/v1/login")
            .json(&json!({
                "email": "admin@test.com",
                "password": "Admin#pass1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .delete(&format!("/v1/restricted/users/{}", user.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let deleted_user = c.user_repository.get_by_id(&user.id).await;
        assert!(deleted_user.is_err());

        let event = c
            .wait_for_event(5, |event| matches!(event, UserEvents::Deleted { .. }))
            .await;

        assert!(event.is_some(), "Should have received some event");

        if let Some(UserEvents::Deleted { user }) = event {
            assert_eq!(user.email, "user@test.com".to_string());
            assert_eq!(user.first_name.unwrap(), "Jon".to_string());
            assert_eq!(user.last_name.unwrap(), "Snow".to_string());
            assert_eq!(user.avatar_path, None);
            assert_eq!(user.roles.is_empty(), true);
        }
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_for_nonexistent_user() {
    run_integration_test_with_default(|c| async move {
        let mut admin = User::now_with_email_and_password(
            String::from("admin@test.com"),
            String::from("Admin#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("ADMIN_USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        admin.add_role(role.clone());
        c.user_repository.save(&admin).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "admin@test.com",
                "password": "Admin#pass1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let non_existent_id = Uuid::new_v4();
        let response = c
            .server
            .get(&format!("/v1/restricted/users/{}", non_existent_id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn it_updates_other_user_information() {
    run_integration_test_with_default(|c| async move {
        let mut admin = User::now_with_email_and_password(
            String::from("admin@test.com"),
            String::from("Admin#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("ADMIN_USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        admin.add_role(role.clone());
        c.user_repository.save(&admin).await.unwrap();

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
            .post("/v1/login")
            .json(&json!({
                "email": "admin@test.com",
                "password": "Admin#pass1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .put(&format!("/v1/restricted/users/{}", user.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
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

        let event = c
            .wait_for_event(5, |event| matches!(event, UserEvents::Updated { .. }))
            .await;

        assert!(event.is_some(), "Should have received some event");

        if let Some(UserEvents::Updated { old_user, new_user }) = event {
            assert_eq!(old_user.first_name, Some("Jon".to_string()));
            assert_eq!(old_user.last_name, Some("Snow".to_string()));
            assert_eq!(old_user.avatar_path, None);
            assert_eq!(old_user.roles.is_empty(), true);

            assert_eq!(new_user.email, "user@test.com".to_string());
            assert_eq!(new_user.first_name.unwrap(), "Jon".to_string());
            assert_eq!(new_user.last_name.unwrap(), "Doe".to_string());
            assert_eq!(
                new_user.avatar_path,
                Some("https://somepath.com/123.jpg".to_string())
            );
            assert_eq!(new_user.roles.is_empty(), true);
        }
    })
    .await;
}

#[tokio::test]
async fn it_cannot_update_none_existing_user() {
    run_integration_test_with_default(|c| async move {
        let mut admin = User::now_with_email_and_password(
            String::from("admin@test.com"),
            String::from("Admin#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        admin.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("ADMIN_USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        admin.add_role(role.clone());
        c.user_repository.save(&admin).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "admin@test.com",
                "password": "Admin#pass1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .put(&format!("/v1/restricted/users/{}", Uuid::new_v4()))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
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
