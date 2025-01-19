use crate::acceptance::utils::create_admin_with_token;
use crate::utils::runners::run_integration_test;
use auth_service::api::dto::{LoginResponse, MessageResponse, SessionListResponse};
use auth_service::application::service::auth_service::AuthStrategy;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::session::Session;
use auth_service::domain::user::{PasswordHandler, User};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn it_returns_not_found_for_nonexistent_session() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let (_, access_token) = create_admin_with_token(&c).await;
            let non_existent_id = Uuid::new_v4();

            let response = c
                .server
                .get(&format!("/v1/restricted/sessions/{}", non_existent_id))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
            let body = response.json::<MessageResponse>();
            assert_eq!(
                body.message,
                format!("Session not found with id: {}", non_existent_id)
            );
        },
    )
    .await;
}

#[tokio::test]
async fn it_can_list_sessions() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let (_, access_token) = create_admin_with_token(&c).await;

            let user = User::now_with_email_and_password(
                String::from("user@test.com"),
                String::from("User#pass1"),
                None,
                None,
                Some(true),
            )
            .unwrap();
            c.user_repository.save(&user).await.unwrap();

            let session1 = Session::now(user.id, Utc::now() + Duration::hours(1));
            let session2 = Session::now(user.id, Utc::now() + Duration::hours(1));
            c.session_repository.save(&session1).await.unwrap();
            c.session_repository.save(&session2).await.unwrap();

            let response = c
                .server
                .get("/v1/restricted/sessions?page=1&limit=10")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
            let body = response.json::<SessionListResponse>();
            assert_eq!(body.items.len(), 3);
            assert_eq!(body.total, 3);
            assert_eq!(body.page, 1);
            assert_eq!(body.limit, 10);
            assert_eq!(body.pages, 1);
        },
    )
    .await;
}

#[tokio::test]
async fn it_can_get_session_by_id() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let (_, access_token) = create_admin_with_token(&c).await;

            let user = User::now_with_email_and_password(
                String::from("user@test.com"),
                String::from("User#pass1"),
                None,
                None,
                Some(true),
            )
            .unwrap();
            c.user_repository.save(&user).await.unwrap();

            let session = Session::now(user.id, Utc::now() + Duration::hours(1));
            c.session_repository.save(&session).await.unwrap();

            let response = c
                .server
                .get(&format!("/v1/restricted/sessions/{}", session.id))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
            let body = response.json::<Session>();
            assert_eq!(body.id, session.id);
            assert_eq!(body.user_id, user.id);
        },
    )
    .await;
}

#[tokio::test]
async fn it_can_delete_session() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let (_, access_token) = create_admin_with_token(&c).await;

            let user = User::now_with_email_and_password(
                String::from("user@test.com"),
                String::from("User#pass1"),
                None,
                None,
                Some(true),
            )
            .unwrap();
            c.user_repository.save(&user).await.unwrap();

            let session = Session::now(user.id, Utc::now() + Duration::hours(1));
            c.session_repository.save(&session).await.unwrap();

            let response = c
                .server
                .delete(&format!("/v1/restricted/sessions/{}", session.id))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
            let body = response.json::<MessageResponse>();
            assert_eq!(body.message, "Session deleted successfully");

            let deleted_session = c.session_repository.get_by_id(&session.id).await;
            assert!(deleted_session.is_err());
        },
    )
    .await;
}

#[tokio::test]
async fn it_cannot_access_sessions_without_admin_role() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let mut user = User::now_with_email_and_password(
                String::from("user@test.com"),
                String::from("User#pass1"),
                None,
                None,
                Some(true),
            )
            .unwrap();
            user.hash_password(&SchemeAwareHasher::default()).unwrap();
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

            let list_response = c
                .server
                .get("/v1/restricted/sessions?page=1&limit=10")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
                )
                .await;

            assert_eq!(list_response.status_code(), StatusCode::FORBIDDEN);

            let get_response = c
                .server
                .get(&format!("/v1/restricted/sessions/{}", Uuid::new_v4()))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
                )
                .await;

            assert_eq!(get_response.status_code(), StatusCode::FORBIDDEN);

            let delete_response = c
                .server
                .delete(&format!("/v1/restricted/sessions/{}", Uuid::new_v4()))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
                )
                .await;

            assert_eq!(delete_response.status_code(), StatusCode::FORBIDDEN);
        },
    )
    .await;
}

#[tokio::test]
async fn it_can_delete_all_user_sessions() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let (_, access_token) = create_admin_with_token(&c).await;

            let user = User::now_with_email_and_password(
                String::from("user@test.com"),
                String::from("User#pass1"),
                None,
                None,
                Some(true),
            )
            .unwrap();
            c.user_repository.save(&user).await.unwrap();

            let session1 = Session::now(user.id, Utc::now() + Duration::hours(1));
            let session2 = Session::now(user.id, Utc::now() + Duration::hours(1));
            c.session_repository.save(&session1).await.unwrap();
            c.session_repository.save(&session2).await.unwrap();

            let response = c
                .server
                .delete(&format!("/v1/restricted/users/{}/sessions", user.id))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
            let body = response.json::<MessageResponse>();
            assert_eq!(body.message, "All sessions deleted successfully");

            let remaining_sessions = c.session_repository.get_by_user_id(&user.id).await.unwrap();
            assert_eq!(remaining_sessions.len(), 0);
        },
    )
    .await;
}

#[tokio::test]
async fn it_returns_not_found_when_deleting_sessions_for_nonexistent_user() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let (_, access_token) = create_admin_with_token(&c).await;
            let non_existent_id = Uuid::new_v4();

            let response = c
                .server
                .delete(&format!(
                    "/v1/restricted/users/{}/sessions",
                    non_existent_id
                ))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
            let body = response.json::<MessageResponse>();
            assert_eq!(
                body.message,
                format!("User not found with id: {}", non_existent_id)
            );
        },
    )
    .await;
}

#[tokio::test]
async fn it_cannot_delete_own_session() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let (_, access_token) = create_admin_with_token(&c).await;

            let response = c
                .server
                .get("/v1/restricted/sessions?page=1&limit=10")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
            let sessions = response.json::<SessionListResponse>();
            let admin_session = sessions.items.first().expect("Admin should have a session");

            let response = c
                .server
                .delete(&format!("/v1/restricted/sessions/{}", admin_session.id))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
            let body = response.json::<MessageResponse>();
            assert_eq!(body.message, "Cannot delete your own session");

            let session = c.session_repository.get_by_id(&admin_session.id).await;
            assert!(session.is_ok());
        },
    )
    .await;
}

#[tokio::test]
async fn it_cannot_delete_own_user_sessions() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let (admin, access_token) = create_admin_with_token(&c).await;

            let response = c
                .server
                .delete(&format!("/v1/restricted/users/{}/sessions", admin.id))
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
            let body = response.json::<MessageResponse>();
            assert_eq!(body.message, "Cannot delete your own sessions");

            let response = c
                .server
                .get("/v1/restricted/sessions?page=1&limit=10")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", access_token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
            let sessions = response.json::<SessionListResponse>();
            assert!(
                !sessions.items.is_empty(),
                "Admin sessions should still exist"
            );
        },
    )
    .await;
}
