mod domain;
mod infrastructure;

use axum::{
    routing::{get},
    http::StatusCode,
    Json, Router,
};
use serde::{Serialize};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/v1/health", get(health));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await;
    match listener {
        Ok(listener) => {
            println!("Server started at http://localhost:8080");
            axum::serve(listener, app).await.unwrap();
        }
        Err(e) => {
            println!("Failed to bind to port 8080: {}", e);
        }
    }
}

async fn health() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { message: String::from("OK") }))
}

#[derive(Serialize)]
struct HealthResponse {
    message: String,
}
