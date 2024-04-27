use crate::create_test_server;
use ::serde_json::json;
use axum::http::StatusCode;
use sqlx::{MySql, Pool};

#[sqlx::test]
async fn it_registers_new_user(pool: Pool<MySql>) {
    let server = create_test_server(pool);
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
    let server = create_test_server(pool);
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
