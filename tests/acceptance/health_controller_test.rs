use axum::{http::StatusCode};
use auth_service::api::health_controller::HealthResponse;
use crate::acceptance::test_server::*;

#[tokio::test]
async fn it_returns_ok() {
    let server = create_test_server();
    let response = server.get("/v1/health").await;
    let body = response.json::<HealthResponse>();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(body.message, "OK");
}
