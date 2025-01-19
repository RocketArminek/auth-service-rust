use axum::http::{HeaderName, HeaderValue, StatusCode};
use serde_json::json;
use uuid::Uuid;
use auth_service::api::dto::{CreatedResponse, LoginResponse, RoleListResponse, RoleResponse};
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use crate::acceptance::utils;
use crate::utils::runners::run_integration_test_with_default;

#[tokio::test]
async fn it_can_create_role() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::create_admin_with_token(&c).await;

        let response = c
            .server
            .post("/v1/restricted/roles")
            .json(&json!({
                "name": "TEST_ROLE"
            }))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::CREATED);
        let body = response.json::<CreatedResponse>();
        assert!(!body.id.is_empty());

        let role = c.role_repository.get_by_name("TEST_ROLE").await.unwrap();
        assert_eq!(role.name, "TEST_ROLE");
    })
        .await;
}

#[tokio::test]
async fn it_cannot_create_duplicate_role() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::create_admin_with_token(&c).await;
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let response = c
            .server
            .post("/v1/restricted/roles")
            .json(&json!({
                "name": "TEST_ROLE"
            }))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::CONFLICT);
    })
        .await;
}

#[tokio::test]
async fn it_can_list_roles_with_pagination() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::create_admin_with_token(&c).await;

        for i in 1..=15 {
            let role = Role::now(format!("TEST_ROLE_{}", i)).unwrap();
            c.role_repository.save(&role).await.unwrap();
        }

        let response = c
            .server
            .get("/v1/restricted/roles?page=1&limit=10")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<RoleListResponse>();
        assert_eq!(body.roles.len(), 10);

        let response = c
            .server
            .get("/v1/restricted/roles?page=2&limit=10")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<RoleListResponse>();
        assert_eq!(body.roles.len(), 6);
    })
        .await;
}

#[tokio::test]
async fn it_can_get_role_by_id() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::create_admin_with_token(&c).await;
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let response = c
            .server
            .get(&format!("/v1/restricted/roles/{}", role.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<RoleResponse>();
        assert_eq!(body.name, "TEST_ROLE");
        assert_eq!(body.id, role.id.to_string());
    })
        .await;
}

#[tokio::test]
async fn it_returns_not_found_for_nonexistent_role() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::create_admin_with_token(&c).await;
        let role_id = Uuid::new_v4();

        let response = c
            .server
            .get(&format!("/v1/restricted/roles/{}", role_id))
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
async fn it_can_delete_role() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::create_admin_with_token(&c).await;
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let response = c
            .server
            .delete(&format!("/v1/restricted/roles/{}", role.id))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

        let result = c.role_repository.get_by_id(&role.id).await;
        assert!(result.is_err());
    })
        .await;
}

#[tokio::test]
async fn it_requires_admin_role() {
    run_integration_test_with_default(|c| async move {
        let mut user = User::now_with_email_and_password(
            String::from("user@test.com"),
            String::from("User#pass1"),
            Some(String::from("Regular")),
            Some(String::from("User")),
            Some(true),
        )
            .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        let role = Role::now("USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        user.add_role(role);
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "user@test.com",
                "password": "User#pass1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .get("/v1/restricted/roles")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    })
        .await;
}

#[tokio::test]
async fn it_can_assign_role_to_user() {
    run_integration_test_with_default(|c| async move {
        let (_, token) = utils::create_admin_with_token(&c).await;

        let user = User::now_with_email_and_password(
            "test@example.com".to_string(),
            "Test#pass123".to_string(),
            None,
            None,
            Some(true),
        )
            .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let response = c
            .server
            .patch(&format!("/v1/restricted/users/{}/roles", user.id))
            .json(&json!({
                "role": "TEST_ROLE"
            }))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let updated_user = c.user_repository.get_by_id(&user.id).await.unwrap();
        assert!(updated_user.has_role("TEST_ROLE".to_string()));
    })
        .await;
}
