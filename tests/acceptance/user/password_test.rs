use crate::utils::runners::run_integration_test_with_default;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::{Claims, TokenType, UserDTO};
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::ops::Add;

#[tokio::test]
async fn it_cannot_reset_password_if_user_does_not_exist() {
    run_integration_test_with_default(|c| async move {
        let response = c
            .server
            .post("/v1/password/reset")
            .json(&json!({
                "email": "user@test.com",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    })
    .await;
}

#[tokio::test]
async fn it_can_reset_password() {
    run_integration_test_with_default(|mut c| async move {
        let email = String::from("user@test.com");
        let password = String::from("User#pass1");
        let mut user = User::now_with_email_and_password(
            email.clone(),
            password.clone(),
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

        let user_dto = UserDTO::from(user);
        let now = Utc::now();

        let rp_duration = Duration::new(10, 0).unwrap_or_default();
        let rp_exp = now.add(rp_duration);

        let rp_body = Claims::new(
            rp_exp.timestamp() as usize,
            user_dto.clone(),
            TokenType::Password,
            None,
        );

        let token = encode(
            &Header::default(),
            &rp_body,
            &EncodingKey::from_secret("secret".as_bytes()),
        )
        .unwrap();

        let new_password = String::from("User#pass1New");
        let response = c
            .server
            .patch("/v1/me/password/reset")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
            )
            .json(&json!({
                "password": new_password,
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        c.tester
            .assert_event_published(
                |event| match event {
                    Some(UserEvents::PasswordReset { user }) => {
                        assert_eq!(user.email, email);
                    }
                    _ => panic!("Got {:?}", event),
                },
                5,
            )
            .await;

        let login_response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": &new_password,
            }))
            .await;

        assert_eq!(login_response.status_code(), StatusCode::OK);

        let login_response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": &password,
            }))
            .await;

        assert_eq!(login_response.status_code(), StatusCode::UNAUTHORIZED);
    })
    .await;
}
