use ::serde_json::json;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::jwt::Claims;
use auth_service::domain::user::{PasswordHandler, User};
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::{MySql, Pool};
use std::ops::{Add, Sub};
use auth_service::api::dto::{MessageResponse, TokenResponse};
use crate::utils::create_test_server;

#[sqlx::test]
async fn it_returns_not_found_if_user_does_not_exist(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());

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
    let server = create_test_server("secret".to_string(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(email.clone(), String::from("Iknow#othing1")).unwrap();
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
async fn it_returns_session_for_authenticated_user(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(email.clone(), String::from("Iknow#othing1")).unwrap();
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

    let body = response.json::<TokenResponse>();
    let exp = Utc::now().add(Duration::days(30));

    assert_eq!(body.user_id, user.id.to_string());
    assert_eq!(body.email, user.email);
    assert_eq!(body.expires_at, exp.timestamp() as usize);
    assert!(body.token.len() > 0);

    let token = decode::<Claims>(
        &body.token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    ).unwrap();

    assert_eq!(token.claims.sub, user.id.to_string());
    assert_eq!(token.claims.email, user.email);
    assert_eq!(token.claims.iss, "rocket-arminek");
    assert_eq!(token.claims.exp, exp.timestamp() as usize);
}

#[sqlx::test]
async fn it_verifies_token(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(email.clone(), String::from("Iknow#othing1")).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<TokenResponse>();

    let response = server
        .get("/v1/stateless/verify")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.token)).unwrap(),
        )
        .await;

    let user_id_from_header = response.headers().get("X-User-Id").unwrap().to_str().unwrap();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(user_id_from_header, user.id.to_string());
}

#[sqlx::test]
async fn it_returns_unauthorized_when_token_is_invalid(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(email.clone(), String::from("Iknow#othing1")).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let mut body = response.json::<TokenResponse>();

    body.token.push('1');

    let response = server
        .get("/v1/stateless/verify")
        .add_header(
            header::AUTHORIZATION,
            HeaderValue::try_from(format!("Bearer {}", body.token)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn it_returns_unauthorized_when_token_is_expired(pool: Pool<MySql>) {
    let secret = "secret".to_string();
    let server = create_test_server(secret.clone(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let mut user =
        User::now_with_email_and_password(email.clone(), String::from("Iknow#othing1")).unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    repository.add(&user).await.unwrap();

    let now = Utc::now();
    let exp = now.sub(Duration::days(2));

    let claims = Claims::new(
        user.id.to_string().clone(),
        exp.timestamp() as usize,
        "rocket-arminek".to_string(),
        user.email.clone(),
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
