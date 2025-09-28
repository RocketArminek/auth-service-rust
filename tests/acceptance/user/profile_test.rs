use std::ops::Add;
use crate::utils::runners::run_integration_test_with_default;
use auth_service::api::dto::LoginResponse;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::{Claims, TokenType, UserDTO};
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;

#[tokio::test]
async fn it_updates_user_information() {
    run_integration_test_with_default(|mut c| async move {
        let mut user = User::now_with_email_and_password(
            String::from("user@test.com"),
            String::from("User#pass1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        user.add_role(role.clone());
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
            .put("/v1/me")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .json(&json!({
                "firstName": "Jon",
                "lastName": "Doe",
                "avatarPath": "https://somepath.com/123.jpg"
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
                    assert_eq!(old_user.email, "user@test.com".to_string());
                    assert_eq!(old_user.first_name, Some("Jon".to_string()));
                    assert_eq!(old_user.last_name, Some("Snow".to_string()));
                    assert_eq!(old_user.avatar_path, None);
                    assert_eq!(old_user.roles, vec!["USER".to_string()]);

                    assert_eq!(new_user.email, "user@test.com".to_string());
                    assert_eq!(new_user.first_name.unwrap(), "Jon".to_string());
                    assert_eq!(new_user.last_name.unwrap(), "Doe".to_string());
                    assert_eq!(
                        new_user.avatar_path,
                        Some("https://somepath.com/123.jpg".to_string())
                    );
                    assert_eq!(new_user.roles, vec!["USER".to_string()]);
                }
                _ => panic!("Got {:?}", event),
            }
        }, 5).await;
    })
    .await;
}

#[tokio::test]
async fn it_produces_user_account_verification_requested() {
    run_integration_test_with_default(|mut c| async move {
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        let email = String::from("jon@snow.test");
        let password = String::from("Iknow#othing1");

        let _ = c
            .server
            .post("/v1/users")
            .json(&json!({
                "email": &email,
                "password": &password,
                "role": "user",
            }))
            .await;

        c.tester.assert_event_published(|event| {
            match event {
                Some(UserEvents::Created { user }) => {
                    assert_eq!(user.email, "jon@snow.test");
                }
                _ => panic!("Got {:?}", event),
            }
        }, 5).await;

        c.tester.assert_event_published(|event| {
            match event {
                Some(UserEvents::VerificationRequested {  user, .. }) => {
                    assert_eq!(user.email, "jon@snow.test");
                }
                _ => panic!("Got {:?}", event),
            }
        }, 5).await;
    })
    .await
}

#[tokio::test]
async fn it_verifies_user_account_base_on_token() {
    run_integration_test_with_default(|mut c| async move {
        let email = String::from("user@test.com");
        let password = String::from("User#pass1");
        let mut user = User::now_with_email_and_password(
            email.clone(),
            password.clone(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(false),
        )
            .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();

        let role = Role::now("USER".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        user.add_role(role.clone());
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": &password,
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body = response.json::<LoginResponse>();

        let user_dto = UserDTO::from(user);
        let now = Utc::now();
        let vr_duration = Duration::new(10, 0)
            .unwrap_or_default();
        let vr_exp = now.add(vr_duration);

        let vr_body = Claims::new(
            vr_exp.timestamp() as usize,
            user_dto.clone(),
            TokenType::Verification,
            None,
        );

        let token = encode(
            &Header::default(),
            &vr_body,
            &EncodingKey::from_secret("secret".as_bytes()),
        ).unwrap();

        let response = c
            .server
            .patch("/v1/me/verification")
            .json(&json!({
                "token": &token,
            }))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let body = response.json::<UserDTO>();

        assert!(body.is_verified);
        assert_eq!(body.email, email);
        assert_eq!(body.roles, vec!["USER".to_string()]);

        c.tester.assert_event_published(|event| {
            match event {
                Some(UserEvents::Verified { user }) => {
                    assert_eq!(user.email, "user@test.com");
                }
                _ => panic!("Got {:?}", event),
            }
        }, 5).await;
    }).await
}

#[tokio::test]
async fn it_can_request_for_resend_verification_message() {
    run_integration_test_with_default(|mut c| async move {
        let role = Role::now("NIGHT_WATCH".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let email = String::from("jon@snow.test");
        let password = String::from("Iknow#othing1");
        let mut user = User::now_with_email_and_password(
            email.clone(),
            password.clone(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(false),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        user.add_role(role);
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": &password,
            }))
            .await;
        let login_body = response.json::<LoginResponse>();

        let response = c
            .server
            .post("/v1/me/verification/resend")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", login_body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        c.tester.assert_event_published(|event| {
            match event {
                Some(UserEvents::VerificationRequested { user, .. }) => {
                    assert_eq!(user.email, "jon@snow.test");
                }
                _ => panic!("Got {:?}", event),
            }
        }, 5).await;
    })
    .await
}
