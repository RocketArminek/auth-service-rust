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
            "password": "password",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
}
