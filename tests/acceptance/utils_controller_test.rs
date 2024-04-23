use crate::create_test_server;
use auth_service::api::utils_controller::HealthResponse;
use axum::http::StatusCode;

#[tokio::test]
async fn it_returns_health_check_result() {
    let server = create_test_server();
    let response = server.get("/v1/health").await;
    let body = response.json::<HealthResponse>();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(body.message, "OK");
}

#[tokio::test]
async fn it_returns_open_api_docs() {
    let server = create_test_server();
    let response = server.get("/").await;
    let body = response.text();

    assert_eq!(response.status_code(), StatusCode::OK);
    assert!(body.contains("openapi"));
}
