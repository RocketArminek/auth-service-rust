use ::serde_json::json;
use auth_service::domain::crypto::{HashingScheme, SchemeAwareHasher};
use auth_service::domain::jwt::{Claims, TokenType, UserDTO};
use auth_service::domain::user::{PasswordHandler, User};
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::{MySql, Pool};
use std::ops::{Add, Sub};
use auth_service::api::dto::{LoginResponse, MessageResponse};
use auth_service::domain::role::Role;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use crate::utils::create_test_server;

#[sqlx::test]
async fn it_returns_not_found_if_user_does_not_exist(pool: Pool<MySql>) {
    let server = create_test_server(
        "secret".to_string(),
        pool.clone(),
        HashingScheme::BcryptLow,
        None,
        60,
        60,
        true
    ).await;

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "jon@snow.test",
            "password": "Iknow#oth1ng",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn it_returns_unauthorized_for_invalid_password(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "some-bad-password",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn it_issues_access_token(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let at_duration = 60;
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, at_duration, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body = response.json::<LoginResponse>();
    let exp = Utc::now().add(Duration::new(at_duration, 0).unwrap_or_default());

    assert_eq!(body.user.id, user.id);
    assert_eq!(body.user.email, user.email);
    assert_eq!(body.access_token.expires_at, exp.timestamp() as usize);
    assert!(body.access_token.value.len() > 0);

    let token = decode::<Claims>(
        &body.access_token.value,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ).unwrap();

    assert_eq!(token.claims.user.id, user.id);
    assert_eq!(token.claims.user.email, user.email);
    assert_eq!(token.claims.exp, exp.timestamp() as usize);
}

#[sqlx::test]
async fn it_issues_refresh_token(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let rt_duration = 300;
    let server = create_test_server(
        secret.clone(),
        pool.clone(),
        HashingScheme::BcryptLow,
        None,
        60,
        rt_duration,
        true
    ).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body = response.json::<LoginResponse>();
    let exp = Utc::now().add(Duration::new(rt_duration, 0).unwrap_or_default());

    assert_eq!(body.user.id, user.id);
    assert_eq!(body.user.email, user.email);
    assert_eq!(body.refresh_token.expires_at, exp.timestamp() as usize);
    assert!(body.refresh_token.value.len() > 0);

    let token = decode::<Claims>(
        &body.refresh_token.value,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ).unwrap();

    assert_eq!(token.claims.user.id, user.id);
    assert_eq!(token.claims.exp, exp.timestamp() as usize);
}

#[sqlx::test]
async fn it_auto_updates_password_scheme(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::with_scheme(HashingScheme::Bcrypt));
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let found_user = repository.get_by_id(user.id).await.unwrap();
    let parts: Vec<&str> = found_user.password.splitn(2, '.').collect();
    let scheme = HashingScheme::from_string(parts[0].to_string()).unwrap();

    assert_eq!(scheme, HashingScheme::BcryptLow)
}

#[sqlx::test]
async fn it_verifies_token(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&user, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .get("/v1/stateless/verify")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .await;

    let user_id_from_header = response.headers().get("X-User-Id").unwrap().to_str().unwrap();
    let roles_from_header = response.headers().get("X-User-Roles").unwrap().to_str().unwrap();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(user_id_from_header, user.id.to_string());
    assert!(roles_from_header.contains("user"));
}

#[sqlx::test]
async fn it_does_not_verify_token_by_using_refresh_token(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&user, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .get("/v1/stateless/verify")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.refresh_token.value)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn it_refreshes_token(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&user, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .post("/v1/stateless/refresh")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.refresh_token.value)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body = response.json::<LoginResponse>();
    let exp = Utc::now().add(Duration::new(60, 0).unwrap_or_default());

    assert_eq!(body.user.id, user.id);
    assert_eq!(body.user.email, user.email);
    assert_eq!(body.access_token.expires_at, exp.timestamp() as usize);
    assert!(body.access_token.value.len() > 0);

    let token = decode::<Claims>(
        &body.access_token.value,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ).unwrap();

    assert_eq!(token.claims.user.id, user.id);
    assert_eq!(token.claims.user.email, user.email);
    assert_eq!(token.claims.exp, exp.timestamp() as usize);
}

#[sqlx::test]
async fn it_does_not_refresh_token_if_token_is_not_valid(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&user, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/refresh")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from("Bearer notValidToken".to_string()).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn it_does_not_refresh_if_you_use_access_token(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&user, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .post("/v1/stateless/refresh")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn it_returns_unauthorized_when_token_is_invalid(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let mut body = response.json::<LoginResponse>();

    body.access_token.value.push('1');

    let response = server
        .get("/v1/stateless/verify")
        .add_header(
            header::AUTHORIZATION,
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn it_returns_unauthorized_when_token_is_expired(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true).await;
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    repository.add(&user).await.unwrap();

    let now = Utc::now();
    let exp = now.sub(Duration::days(2));
    
    let claims = Claims::new(
        exp.timestamp() as usize,
        UserDTO {
            id: user.id,
            email: user.email.clone(),
            roles: vec!["ADMIN_USER".to_string()],
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            avatar_path: user.avatar_path.clone(),
        },
        TokenType::Access
    );
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
        .unwrap();

    let response = server
        .get("/v1/stateless/verify")
        .add_header(
            header::AUTHORIZATION,
            HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
        )
        .await;

    let body = response.json::<MessageResponse>();

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(body.message, "Expired token");
}
