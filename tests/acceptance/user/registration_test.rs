use crate::utils::runners::{run_integration_test, run_integration_test_with_default};
use auth_service::api::dto::MessageResponse;
use auth_service::domain::event::UserEvents;
use auth_service::domain::role::Role;
use auth_service::domain::user::User;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn it_creates_new_user() {
    run_integration_test(
        |b| {
            b.app.verification_required(false);
        },
        |c| async move {
            let role = Role::now("user".to_string()).unwrap();
            c.role_repository.save(&role).await.unwrap();
            let email = String::from("jon@snow.test");
            let response = c
                .server
                .post("/v1/users")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                    "role": "user",
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::CREATED);

            let event = c
                .wait_for_event(5, |event| matches!(event, UserEvents::Created { .. }))
                .await;

            assert!(event.is_some(), "Should have received some event");

            if let Some(UserEvents::Created { user }) = event {
                assert_eq!(user.email, email);
                assert_eq!(user.first_name, None);
                assert_eq!(user.last_name, None);
                assert_eq!(user.avatar_path, None);
                assert_eq!(user.roles, vec!["user".to_string()]);
                assert_eq!(user.is_verified, true);
            }
        },
    )
    .await
}

#[tokio::test]
async fn it_creates_not_verified_user() {
    run_integration_test_with_default(|c| async move {
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        let email = String::from("jon@snow.test");

        let response = c
            .server
            .post("/v1/users")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
                "role": "user",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::CREATED);

        let event = c
            .wait_for_event(5, |event| matches!(event, UserEvents::Created { .. }))
            .await;

        assert!(event.is_some(), "Should have received some event");

        if let Some(UserEvents::Created { user }) = event {
            assert_eq!(user.email, email);
            assert_eq!(user.first_name, None);
            assert_eq!(user.last_name, None);
            assert_eq!(user.avatar_path, None);
            assert_eq!(user.roles, vec!["user".to_string()]);
            assert_eq!(user.is_verified, false);
        }

        let event = c
            .wait_for_event(5, |event| {
                matches!(event, UserEvents::VerificationRequested { .. })
            })
            .await;

        assert!(event.is_some(), "Should have received some event");

        if let Some(UserEvents::VerificationRequested { user, token }) = event {
            assert_eq!(user.email, email);
            assert_eq!(user.first_name, None);
            assert_eq!(user.last_name, None);
            assert_eq!(user.avatar_path, None);
            assert_eq!(user.roles, vec!["user".to_string()]);
            assert_eq!(user.is_verified, false);
            assert_eq!(token.is_empty(), false);
        }
    })
    .await
}

#[tokio::test]
async fn it_does_not_create_user_with_invalid_password() {
    run_integration_test_with_default(|c| async move {
        let email = String::from("jon@snow.test");
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let response = c
            .server
            .post("/v1/users")
            .json(&json!({
                "email": &email,
                "password": "wrong",
                "role": "user",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

        let event = c.wait_for_event(5, |_| true).await;
        assert!(event.is_none(), "Should not receive any message");
    })
    .await
}

#[tokio::test]
async fn it_returns_conflict_if_user_already_exists() {
    run_integration_test_with_default(|c| async move {
        let email = String::from("jon@snow.test");
        let user = User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let response = c
            .server
            .post("/v1/users")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
                "role": "user",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::CONFLICT);
    })
    .await;
}

#[tokio::test]
async fn it_returns_bad_request_if_roles_does_not_exists() {
    run_integration_test_with_default(|c| async move {
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        let email = String::from("jon@snow.test");

        let response = c
            .server
            .post("/v1/users")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
                "role": "some_role",
            }))
            .await;
        let body = response.json::<MessageResponse>();

        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(body.message, "Role does not exist");
    })
    .await;
}

#[tokio::test]
async fn it_returns_bad_request_if_role_is_restricted() {
    run_integration_test_with_default(|c| async move {
        let email = String::from("jon@snow.test");
        let roles = vec!["ADMIN", "admin", "ADMIN_USER"];

        for role in roles {
            let response = c
                .server
                .post("/v1/users")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                    "role": role,
                }))
                .await;
            let body = response.json::<MessageResponse>();

            assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
            assert_eq!(body.message, "Role is restricted");
        }
    })
    .await;
}
