use crate::utils::runners::{run_integration_test, run_integration_test_with_default};
use auth_service::api::dto::{LoginResponse, MessageResponse};
use auth_service::application::configuration::dto::{DurationInSeconds, HiddenString};
use auth_service::application::service::auth_service::AuthStrategy;
use auth_service::domain::crypto::{HashingScheme, SchemeAwareHasher};
use auth_service::domain::jwt::{Claims, TokenType, UserDTO};
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde_json::json;
use std::ops::{Add, Sub};

#[tokio::test]
async fn it_returns_not_found_if_user_does_not_exist() {
    run_integration_test_with_default(|c| async move {
        let response = c
            .server
            .post("/v1/login")
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
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
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
async fn it_issues_access_token() {
    run_integration_test_with_default(|c| async move {
        let email = String::from("jon@snow.test");
        let mut user = User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(false),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);

        let body = response.json::<LoginResponse>();

        assert_eq!(body.user.is_verified, false);
    })
    .await;
}

#[tokio::test]
async fn it_issues_access_token_for_not_verified_user() {
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
                Some(false),
            )
            .unwrap();
            user.hash_password(&SchemeAwareHasher::default()).unwrap();
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
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

            let token = decode::<Claims>(
                &body.access_token.value,
                &DecodingKey::from_secret("secret".as_ref()),
                &Validation::default(),
            )
            .unwrap();

            assert_eq!(token.claims.user.id, user.id);
            assert_eq!(token.claims.user.email, user.email);
            assert_eq!(token.claims.exp, exp.timestamp() as usize);
        },
    )
    .await;
}

#[tokio::test]
async fn it_issues_refresh_token() {
    let rt_duration = 300;
    let secret = "secret";
    run_integration_test(
        |c| {
            c.app.rt_duration_in_seconds(DurationInSeconds(rt_duration));
            c.app.secret(HiddenString(secret.to_string()));
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
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);

            let body = response.json::<LoginResponse>();
            let exp = Utc::now().add(Duration::new(rt_duration as i64, 0).unwrap_or_default());

            assert_eq!(body.user.id, user.id);
            assert_eq!(body.user.email, user.email);
            assert_eq!(body.refresh_token.expires_at, exp.timestamp() as usize);
            assert!(body.refresh_token.value.len() > 0);

            let token = decode::<Claims>(
                &body.refresh_token.value,
                &DecodingKey::from_secret(secret.as_ref()),
                &Validation::default(),
            )
            .unwrap();

            assert_eq!(token.claims.user.id, user.id);
            assert_eq!(token.claims.exp, exp.timestamp() as usize);
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
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);

            let found_user = c.user_repository.get_by_id(&user.id).await.unwrap();
            let parts: Vec<&str> = found_user.password.splitn(2, '.').collect();
            let scheme = HashingScheme::from_string(parts[0].to_string()).unwrap();

            assert_eq!(scheme, HashingScheme::BcryptLow)
        },
    )
    .await;
}

#[tokio::test]
async fn it_authenticate_token() {
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
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        user.add_role(role);
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .get("/v1/authenticate")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        let user_id_from_header = response
            .headers()
            .get("X-User-Id")
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
        assert!(roles_from_header.contains("user"));
    })
    .await;
}

#[tokio::test]
async fn it_authenticate_token_for_not_verified_user_if_verification_is_not_required() {
    run_integration_test(
        |c| {
            c.app.verification_required(false);
        },
        |c| async move {
            let email = String::from("jon@snow.test");
            let mut user = User::now_with_email_and_password(
                email.clone(),
                String::from("Iknow#othing1"),
                Some(String::from("Jon")),
                Some(String::from("Snow")),
                Some(false),
            )
            .unwrap();
            user.hash_password(&SchemeAwareHasher::default()).unwrap();
            let role = Role::now("user".to_string()).unwrap();
            c.role_repository.save(&role).await.unwrap();
            user.add_role(role);
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;
            let body = response.json::<LoginResponse>();

            let response = c
                .server
                .get("/v1/authenticate")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
                )
                .await;

            let user_id_from_header = response
                .headers()
                .get("X-User-Id")
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
            assert!(roles_from_header.contains("user"));
        },
    )
    .await;
}

#[tokio::test]
async fn it_does_not_authenticate_token_if_user_is_not_verified() {
    run_integration_test_with_default(|c| async move {
        let email = String::from("jon@snow.test");
        let mut user = User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(false),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        user.add_role(role.clone());
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .get("/v1/authenticate")
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
async fn it_does_not_authenticate_token_by_using_refresh_token() {
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
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        user.add_role(role.clone());
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .get("/v1/authenticate")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.refresh_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn it_refreshes_token() {
    let secret = "secret";
    let at_duration = 60;
    run_integration_test(
        |c| {
            c.app.secret(HiddenString(secret.to_string()));
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
            let role = Role::now("user".to_string()).unwrap();
            c.role_repository.save(&role).await.unwrap();
            user.add_role(role.clone());
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;
            let body = response.json::<LoginResponse>();

            let response = c
                .server
                .post("/v1/refresh")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.refresh_token.value)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);

            let body = response.json::<LoginResponse>();
            let exp = Utc::now().add(Duration::new(at_duration as i64, 0).unwrap_or_default());

            assert_eq!(body.user.id, user.id);
            assert_eq!(body.user.email, user.email);
            assert_eq!(body.access_token.expires_at, exp.timestamp() as usize);
            assert!(body.access_token.value.len() > 0);

            let token = decode::<Claims>(
                &body.access_token.value,
                &DecodingKey::from_secret(secret.as_ref()),
                &Validation::default(),
            )
            .unwrap();

            assert_eq!(token.claims.user.id, user.id);
            assert_eq!(token.claims.user.email, user.email);
            assert_eq!(token.claims.exp, exp.timestamp() as usize);
        },
    )
    .await;
}

#[tokio::test]
async fn it_does_not_refresh_token_if_token_is_not_valid() {
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
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        user.add_role(role.clone());
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/refresh")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from("Bearer notValidToken".to_string()).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn it_does_not_refresh_if_you_use_access_token() {
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
        let role = Role::now("user".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        user.add_role(role.clone());
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
            }))
            .await;
        let body = response.json::<LoginResponse>();

        let response = c
            .server
            .post("/v1/refresh")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn it_returns_unauthorized_when_token_is_invalid() {
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
        c.user_repository.save(&user).await.unwrap();

        let response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": &email,
                "password": "Iknow#othing1",
            }))
            .await;
        let mut body = response.json::<LoginResponse>();

        body.access_token.value.push('1');

        let response = c
            .server
            .get("/v1/authenticate")
            .add_header(
                header::AUTHORIZATION,
                HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn it_returns_unauthorized_when_token_is_expired() {
    let secret = "secret";
    run_integration_test(
        |c| {
            c.app.secret(HiddenString(secret.to_string()));
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
            c.user_repository.save(&user).await.unwrap();

            let now = Utc::now();
            let exp = now.sub(Duration::days(2));

            let claims = Claims::new(
                exp.timestamp() as usize,
                UserDTO::from(user),
                TokenType::Access,
                None,
            );
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_ref()),
            )
            .unwrap();

            let response = c
                .server
                .get("/v1/authenticate")
                .add_header(
                    header::AUTHORIZATION,
                    HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
                )
                .await;

            let body = response.json::<MessageResponse>();

            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
            assert_eq!(body.message, "Expired token");
        },
    )
    .await;
}

#[tokio::test]
async fn it_can_logout_with_valid_token() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
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
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;
            let body = response.json::<LoginResponse>();

            let response = c
                .server
                .post("/v1/logout")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);

            let auth_response = c
                .server
                .get("/v1/authenticate")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
                )
                .await;

            assert_eq!(auth_response.status_code(), StatusCode::UNAUTHORIZED);
        },
    )
    .await;
}

#[tokio::test]
async fn it_returns_unauthorized_on_logout_with_invalid_token() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
        },
        |c| async move {
            let response = c
                .server
                .post("/v1/logout")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from("Bearer invalidtoken").unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        },
    )
    .await;
}

#[tokio::test]
async fn it_returns_unauthorized_on_logout_with_expired_token() {
    let secret = "secret";
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
            c.app.secret(HiddenString(secret.to_string()));
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
            c.user_repository.save(&user).await.unwrap();

            let now = Utc::now();
            let exp = now.sub(Duration::days(2));

            let claims = Claims::new(
                exp.timestamp() as usize,
                UserDTO::from(user),
                TokenType::Access,
                None,
            );
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_ref()),
            )
            .unwrap();

            let response = c
                .server
                .post("/v1/logout")
                .add_header(
                    header::AUTHORIZATION,
                    HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
                )
                .await;

            let body = response.json::<MessageResponse>();

            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
            assert_eq!(body.message, "Expired token");
        },
    )
    .await;
}

#[tokio::test]
async fn it_returns_unauthorized_on_logout_with_refresh_token() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateful);
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
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;
            let body = response.json::<LoginResponse>();

            let response = c
                .server
                .post("/v1/logout")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.refresh_token.value)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        },
    )
    .await;
}

#[tokio::test]
async fn it_does_not_work_for_stateless_auth_strategy() {
    run_integration_test(
        |c| {
            c.app.auth_strategy(AuthStrategy::Stateless);
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
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
                .json(&json!({
                    "email": &email,
                    "password": "Iknow#othing1",
                }))
                .await;
            let body = response.json::<LoginResponse>();

            let response = c
                .server
                .post("/v1/logout")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
            let body_bad_request = response.json::<MessageResponse>();
            assert_eq!(
                body_bad_request.message,
                "Action not supported in this strategy"
            );

            let auth_response = c
                .server
                .get("/v1/authenticate")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
                )
                .await;

            assert_eq!(auth_response.status_code(), StatusCode::OK);
        },
    )
    .await;
}
