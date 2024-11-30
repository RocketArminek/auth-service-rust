use crate::utils::create_test_server;
use auth_service::api::dto::HealthResponse;
use auth_service::domain::crypto::HashingScheme;
use axum::http::StatusCode;
use sqlx::{MySql, Pool};

#[sqlx::test]
async fn it_returns_health_check_result(pool: Pool<MySql>) {
    let server = create_test_server(
        "secret".to_string(),
        pool,
        HashingScheme::BcryptLow,
        None,
        60,
        60,
        true,
    )
    .await;
    let response = server.get("/v1/health").await;
    let body = response.json::<HealthResponse>();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(body.message, "OK");
}

#[sqlx::test]
async fn it_returns_open_api_docs(pool: Pool<MySql>) {
    let server = create_test_server(
        "secret".to_string(),
        pool,
        HashingScheme::BcryptLow,
        None,
        60,
        60,
        true,
    )
    .await;
    let response = server.get("/").await;
    let body = response.text();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(body.contains("openapi"));
}

#[sqlx::test]
async fn it_returns_swagger_ui(pool: Pool<MySql>) {
    let server = create_test_server(
        "secret".to_string(),
        pool,
        HashingScheme::BcryptLow,
        None,
        60,
        60,
        true,
    )
    .await;
    let response = server.get("/docs/").await;
    let body = response.text();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(body.contains("Swagger UI"));
}
