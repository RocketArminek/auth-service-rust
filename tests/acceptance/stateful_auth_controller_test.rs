use crate::utils::runners::{run_integration_test, run_integration_test_with_default};
use ::serde_json::json;
use auth_service::api::dto::{LoginResponse};
use auth_service::application::configuration_types::{DurationInSeconds};
use auth_service::domain::crypto::{HashingScheme, SchemeAwareHasher};
use auth_service::domain::user::{PasswordHandler, User};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use chrono::{Duration, Utc};
use std::ops::{Add};
use auth_service::domain::role::Role;

#[tokio::test]
async fn it_returns_not_found_if_user_does_not_exist() {
    run_integration_test_with_default(|c| async move {
        let response = c
            .server
            .post("/v1/stateful/login")
            .json(&json!({
                "email": "jon@snow.test",
                "password": "Iknow#oth1ng",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn it_returns_unauthorized_for_invalid_password() {
    run_integration_test_with_default(|c| async move {
        let email = String::from("jon@snow.test");
        let mut user = User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        c.user_repository.lock().await.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/stateful/login")
            .json(&json!({
                "email": &email,
                "password": "some-bad-password",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn it_issues_access_token_and_creates_session() {
    let at_duration = 60;
    run_integration_test(
        |c| {
            c.app.at_duration_in_seconds(DurationInSeconds(at_duration));
        },
        |c| async move {
            let email = String::from("jon@snow.test");
            let mut user = User::now_with_email_and_password(
                email.clone(),
                String::from("Iknow#othing1"),
                Some(String::from("Jon")),
                Some(String::from("Snow")),
                Some(true),
            )
            .unwrap();
            user.hash_password(&SchemeAwareHasher::default()).unwrap();
            c.user_repository.lock().await.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/stateful/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);

            let body = response.json::<LoginResponse>();
            let exp = Utc::now().add(Duration::new(at_duration as i64, 0).unwrap_or_default());

            assert_eq!(body.user.id, user.id);
            assert_eq!(body.user.email, user.email);
            assert_eq!(body.access_token.expires_at, exp.timestamp() as usize);
            assert!(body.access_token.value.len() > 0);
            assert!(body.refresh_token.value.len() > 0);

            let session = c
                .session_repository
                .lock()
                .await
                .get_by_user_id(&user.id)
                .await
                .unwrap();

            assert!(!session.is_empty());
        },
    )
    .await;
}

#[tokio::test]
async fn it_auto_updates_password_scheme() {
    run_integration_test(
        |c| {
            c.app.password_hashing_scheme(HashingScheme::BcryptLow);
        },
        |c| async move {
            let email = String::from("jon@snow.test");
            let mut user = User::now_with_email_and_password(
                email.clone(),
                String::from("Iknow#othing1"),
                Some(String::from("Jon")),
                Some(String::from("Snow")),
                Some(true),
            )
            .unwrap();

            user.hash_password(&SchemeAwareHasher::with_scheme(HashingScheme::Bcrypt))
                .unwrap();
            c.user_repository.lock().await.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/stateful/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let found_user = c
                .user_repository
                .lock()
                .await
                .get_by_id(&user.id)
                .await
                .unwrap();
            let parts: Vec<&str> = found_user.password.splitn(2, '.').collect();
            let scheme = HashingScheme::from_string(parts[0].to_string()).unwrap();

            assert_eq!(scheme, HashingScheme::BcryptLow)
        },
    )
    .await;
}

#[tokio::test]
async fn it_verifies_token() {
    run_integration_test_with_default(|c| async move {
        let email = String::from("jon@snow.test");
        let mut user = User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        let role = Role::now("AWESOME".to_string()).unwrap();
        c.role_repository.lock().await.save(&role).await.unwrap();

        user.add_role(role);
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        c.user_repository.lock().await.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/stateful/login")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .get("/v1/stateful/authenticate")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        let session = c.session_repository.lock().await.get_by_user_id(&user.id)
            .await.unwrap().first().unwrap().clone();

        let user_id_from_header = response
            .headers()
            .get("X-User-Id")
            .unwrap()
            .to_str()
            .unwrap();

        let session_id_from_header = response
            .headers()
            .get("X-Session-Id")
            .unwrap()
            .to_str()
            .unwrap();

        let roles_from_header = response
            .headers()
            .get("X-User-Roles")
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(user_id_from_header, user.id.to_string());
        assert_eq!(session_id_from_header, session.id.to_string());
        assert!(roles_from_header.contains("AWESOME"));
    })
    .await;
}

#[tokio::test]
async fn it_logs_out_successfully() {
    run_integration_test_with_default(|c| async move {
        let email = String::from("jon@snow.test");
        let mut user = User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        c.user_repository.lock().await.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/stateful/login")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .post("/v1/stateful/logout")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let sessions = c
            .session_repository
            .lock()
            .await
            .get_by_user_id(&user.id)
            .await
            .unwrap();

        assert!(sessions.is_empty());

        let response = c
            .server
            .get("/v1/stateful/authenticate")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    })
    .await;
}
