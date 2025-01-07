use crate::utils::runners::run_integration_test_with_default;
use auth_service::api::dto::HealthResponse;
use axum::http::StatusCode;

#[tokio::test]
async fn it_returns_health_check_result() {
    run_integration_test_with_default(|c| async move {
        let response = c.server.get("/v1/health").await;
        let body = response.json::<HealthResponse>();

        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(body.message, "OK");
    })
    .await;
}

#[tokio::test]
async fn it_returns_open_api_docs() {
    run_integration_test_with_default(|c| async move {
        let response = c.server.get("/").await;
        let body = response.text();

        assert_eq!(response.status_code(), StatusCode::OK);
        assert!(body.contains("openapi"));
    })
    .await;
}

#[tokio::test]
async fn it_returns_swagger_ui() {
    run_integration_test_with_default(|c| async move {
        let response = c.server.get("/docs/").await;
        let body = response.text();

        assert_eq!(response.status_code(), StatusCode::OK);
        assert!(body.contains("Swagger UI"));
    })
    .await;
}
