use auth_service::api::routes::*;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt::init();
    let port = 8080;
    let addr = &format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(addr).await;

    match listener {
        Ok(listener) => {
            println!("Server started at {}", addr);
            axum::serve(listener, routes()).await.unwrap();
        }
        Err(e) => {
            println!("Failed to bind to port 8080: {}", e);
        }
    }
}
