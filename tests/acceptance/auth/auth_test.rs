use crate::utils::runners::{run_integration_test, run_integration_test_with_default};
use auth_service::api::dto::{LoginResponse, MessageResponse};
use auth_service::application::configuration::dto::DurationInSeconds;
use auth_service::application::service::auth_service::AuthStrategy;
use auth_service::domain::crypto::{HashingScheme, SchemeAwareHasher};
use auth_service::domain::jwt::{Claims, TokenType, UserDTO};
use auth_service::domain::permission::Permission;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
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

        assert!(!body.user.is_verified);
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
            assert!(!body.access_token.value.is_empty());

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
            c.app.secret(secret.to_string());
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
            assert!(!body.refresh_token.value.is_empty());

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
            c.app.secret(secret.to_string());
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
            assert!(!body.access_token.value.is_empty());

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
            c.app.secret(secret.to_string());
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

#[tokio::test]
async fn it_includes_permissions_in_jwt_token() {
    let secret = "secret";
    run_integration_test(
        |c| {
            c.app.secret(secret.to_string());
        },
        |c| async move {
            let role = Role::now("TEST_ROLE".to_string()).unwrap();
            c.role_repository.save(&role).await.unwrap();

            let permission1 = Permission::now(
                "test_permission1".to_string(),
                "test_group1".to_string(),
                Some("Test permission 1".to_string()),
            )
            .unwrap();
            let permission2 = Permission::now(
                "test_permission2".to_string(),
                "test_group1".to_string(),
                Some("Test permission 2".to_string()),
            )
            .unwrap();
            let permission3 = Permission::now(
                "test_permission3".to_string(),
                "test_group2".to_string(),
                Some("Test permission 3".to_string()),
            )
            .unwrap();

            c.permission_repository.save(&permission1).await.unwrap();
            c.permission_repository.save(&permission2).await.unwrap();
            c.permission_repository.save(&permission3).await.unwrap();

            c.role_repository
                .add_permission(&role.id, &permission1.id)
                .await
                .unwrap();
            c.role_repository
                .add_permission(&role.id, &permission2.id)
                .await
                .unwrap();
            c.role_repository
                .add_permission(&role.id, &permission3.id)
                .await
                .unwrap();

            let mut user = User::now_with_email_and_password(
                "test@test.com".to_string(),
                "Test#pass123".to_string(),
                Some("Test".to_string()),
                Some("User".to_string()),
                Some(true),
            )
            .unwrap();
            user.hash_password(&SchemeAwareHasher::default()).unwrap();
            user.add_role(role);
            c.user_repository.save(&user).await.unwrap();

            let response = c
                .server
                .post("/v1/login")
                .json(&json!({
                    "email": "test@test.com",
                    "password": "Test#pass123",
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
            let body = response.json::<LoginResponse>();

            let token = decode::<Claims>(
                &body.access_token.value,
                &DecodingKey::from_secret(secret.as_ref()),
                &Validation::default(),
            )
            .unwrap();

            let permissions = &token.claims.user.permissions;
            assert_eq!(permissions.len(), 2);

            let group1_permissions = permissions.get("test_group1").unwrap();
            assert_eq!(group1_permissions.len(), 2);
            assert!(group1_permissions.contains(&"test_permission1".to_string()));
            assert!(group1_permissions.contains(&"test_permission2".to_string()));

            let group2_permissions = permissions.get("test_group2").unwrap();
            assert_eq!(group2_permissions.len(), 1);
            assert!(group2_permissions.contains(&"test_permission3".to_string()));
        },
    )
    .await;
}

#[tokio::test]
async fn it_includes_permissions_in_authenticate_endpoint() {
    run_integration_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let permission = Permission::now(
            "test_permission".to_string(),
            "test_group".to_string(),
            Some("Test permission".to_string()),
        )
        .unwrap();
        c.permission_repository.save(&permission).await.unwrap();
        c.role_repository
            .add_permission(&role.id, &permission.id)
            .await
            .unwrap();

        let mut user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Test#pass123".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        user.add_role(role);
        c.user_repository.save(&user).await.unwrap();

        let login_response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "test@test.com",
                "password": "Test#pass123",
            }))
            .await;

        let login_body = login_response.json::<LoginResponse>();

        let auth_response = c
            .server
            .get("/v1/authenticate")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", login_body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(auth_response.status_code(), StatusCode::OK);
        let auth_body = auth_response.json::<UserDTO>();

        let permissions = &auth_body.permissions;
        assert_eq!(permissions.len(), 1);

        let group_permissions = permissions.get("test_group").unwrap();
        assert_eq!(group_permissions.len(), 1);
        assert!(group_permissions.contains(&"test_permission".to_string()));
    })
    .await;
}

#[tokio::test]
async fn it_includes_permissions_in_headers() {
    run_integration_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let permission1 = Permission::now(
            "test_permission1".to_string(),
            "test_group1".to_string(),
            Some("Test permission 1".to_string()),
        )
        .unwrap();
        let permission2 = Permission::now(
            "test_permission2".to_string(),
            "test_group1".to_string(),
            Some("Test permission 2".to_string()),
        )
        .unwrap();

        c.permission_repository.save(&permission1).await.unwrap();
        c.permission_repository.save(&permission2).await.unwrap();

        c.role_repository
            .add_permission(&role.id, &permission1.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role.id, &permission2.id)
            .await
            .unwrap();

        let mut user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Test#pass123".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        user.add_role(role);
        c.user_repository.save(&user).await.unwrap();

        let login_response = c
            .server
            .post("/v1/login")
            .json(&json!({
                "email": "test@test.com",
                "password": "Test#pass123",
            }))
            .await;

        let login_body = login_response.json::<LoginResponse>();

        let auth_response = c
            .server
            .get("/v1/authenticate")
            .add_header(
                HeaderName::try_from("Authorization").unwrap(),
                HeaderValue::try_from(format!("Bearer {}", login_body.access_token.value)).unwrap(),
            )
            .await;

        assert_eq!(auth_response.status_code(), StatusCode::OK);

        let permissions_header = auth_response
            .headers()
            .get("X-User-Permissions")
            .unwrap()
            .to_str()
            .unwrap();

        let expected_permissions = "test_group1:test_permission1,test_group1:test_permission2";
        assert_eq!(permissions_header, expected_permissions);
    })
    .await;
}
