use crate::create_test_server;
use ::serde_json::json;
use auth_service::api::user_controller::AuthResponse;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::jwt::Claims;
use auth_service::domain::user::User;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sqlx::{MySql, Pool};
use std::ops::{Add, Sub};

#[sqlx::test]
async fn it_registers_new_user(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool);
    let email = String::from("jon@snow.test");

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
}

#[sqlx::test]
async fn it_does_not_register_user_with_invalid_password(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool);
    let email = String::from("jon@snow.test");

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "wrong",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn it_returns_conflict_if_user_already_exists(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let user =
        User::now_with_email_and_password(email.clone(), String::from("Iknow#othing1")).unwrap();
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CONFLICT);
}

#[sqlx::test]
async fn it_returns_not_found_if_user_does_not_exist(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());

    let response = server
        .post("/v1/users/login")
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
        .post("/v1/users/login")
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
        .post("/v1/users/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body = response.json::<AuthResponse>();
    let exp = Utc::now().add(Duration::days(30));
    match body {
        AuthResponse::OK(body) => {
            assert_eq!(body.user_id, user.id.to_string());
            assert_eq!(body.email, user.email);
            assert_eq!(body.expires_at, exp.timestamp() as usize);
            assert!(body.session_id.len() > 0);
            assert!(body.token.len() > 0);

            let token = decode::<Claims>(
                &body.token,
                &DecodingKey::from_secret(secret.as_ref()),
                &Validation::default(),
            )
            .unwrap();

            assert_eq!(token.claims.sub, user.id.to_string());
            assert_eq!(token.claims.email, user.email);
            assert_eq!(token.claims.iss, "rocket-arminek");
            assert_eq!(token.claims.exp, exp.timestamp() as usize);

            println!("{:?}", body.token);
        }
        _ => panic!("Unexpected response: {:?}", body),
    }
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
        .post("/v1/users/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<AuthResponse>();

    match body {
        AuthResponse::OK(body) => {
            let response = server
                .get("/v1/users/verify")
                .add_header(
                    HeaderName::try_from("Authorization").unwrap(),
                    HeaderValue::try_from(format!("Bearer {}", body.token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
        }
        _ => panic!("Unexpected response: {:?}", body),
    }
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
        .post("/v1/users/login")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<AuthResponse>();

    match body {
        AuthResponse::OK(mut body) => {
            body.token.push('1');

            let response = server
                .get("/v1/users/verify")
                .add_header(
                    header::AUTHORIZATION,
                    HeaderValue::try_from(format!("Bearer {}", body.token)).unwrap(),
                )
                .await;

            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        }
        _ => panic!("Unexpected response: {:?}", body),
    }
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
        .get("/v1/users/verify")
        .add_header(
            header::AUTHORIZATION,
            HeaderValue::try_from(format!("Bearer {}", token)).unwrap(),
        )
        .await;

    let body = response.json::<AuthResponse>();

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    match body {
        AuthResponse::Unauthorized(resp) => {
            assert_eq!(resp.message, "Expired token");
        }
        _ => panic!("Unexpected response: {:?}", body),
    }
}
