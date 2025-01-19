use axum::http::{HeaderName, HeaderValue, StatusCode};
use serde_json::json;
use auth_service::api::dto::LoginResponse;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::event::UserEvents;
use auth_service::domain::jwt::UserDTO;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use crate::utils::runners::run_integration_test_with_default;

#[tokio::test]
async fn it_updates_user_information() {
    run_integration_test_with_default(|c| async move {
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

        let event = c
            .wait_for_event(5, |event| matches!(event, UserEvents::Updated { .. }))
            .await;

        assert!(event.is_some(), "Should have received some event");

        if let Some(UserEvents::Updated { old_user, new_user }) = event {
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
    })
        .await;
}

#[tokio::test]
async fn it_verifies_user_account() {
    run_integration_test_with_default(|c| async move {
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

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
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

        let event = c
            .wait_for_event(5, |event| {
                matches!(event, UserEvents::VerificationRequested { .. })
            })
            .await;

        let Some(UserEvents::VerificationRequested { token, .. }) = event else {
            panic!("Should have received verification requested event")
        };

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

        assert_eq!(body.is_verified, true);
        assert_eq!(body.email, email);
        assert_eq!(body.roles, vec!["user".to_string()]);

        let event = c
            .wait_for_event(5, |event| matches!(event, UserEvents::Verified { .. }))
            .await;

        assert!(event.is_some(), "Should have received some event");
    })
        .await
}

#[tokio::test]
async fn it_can_request_for_resend_verification_message() {
    run_integration_test_with_default(|c| async move {
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

        let event = c
            .wait_for_event(5, |event| {
                matches!(event, UserEvents::VerificationRequested { .. })
            })
            .await;

        let Some(UserEvents::VerificationRequested { token, .. }) = event else {
            panic!("Should have received verification requested event")
        };

        let response = c
            .server
            .patch("/v1/me/verification")
            .json(&json!({
                "token": token,
            }))
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", login_body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let body = response.json::<UserDTO>();

        assert_eq!(body.is_verified, true);
        assert_eq!(body.email, email);
        assert_eq!(body.roles, vec!["NIGHT_WATCH".to_string()]);

        let event = c
            .wait_for_event(5, |event| matches!(event, UserEvents::Verified { .. }))
            .await;

        assert!(event.is_some(), "Should have received some event");
    })
        .await
}
