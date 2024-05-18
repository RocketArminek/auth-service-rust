use ::serde_json::json;
use auth_service::domain::user::User;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::http::{StatusCode};
use sqlx::{MySql, Pool};
use crate::utils::create_test_server;

#[sqlx::test]
async fn it_creates_new_user(pool: Pool<MySql>) {
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
async fn it_does_not_create_user_with_invalid_password(pool: Pool<MySql>) {
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
