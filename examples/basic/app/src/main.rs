use axum::{
    extract::Request,
    response::IntoResponse,
    routing::any,
    Router,
};
use serde::Serialize;
use std::collections::HashMap;
use tower_http::trace::TraceLayer;

#[derive(Serialize)]
struct RequestInfo {
    method: String,
    uri: String,
    host: String,
    headers: HashMap<String, String>,
    forwarded_headers: HashMap<String, String>,
    user_info: UserInfo,
}

#[derive(Serialize)]
struct UserInfo {
    id: Option<String>,
    roles: Option<String>,
    permissions: Option<String>,
}

async fn handle_request(req: Request) -> impl IntoResponse {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let host = req
        .headers()
        .get("X-Forwarded-Host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let mut headers = HashMap::new();
    let mut forwarded_headers = HashMap::new();
    
    for (key, value) in req.headers() {
        let header_value = value.to_str().unwrap_or("").to_string();
        
        if key.as_str().starts_with("x-") {
            forwarded_headers.insert(key.as_str().to_string(), header_value);
        } else {
            headers.insert(key.as_str().to_string(), header_value);
        }
    }

    let user_info = UserInfo {
        id: req.headers().get("x-user-id").and_then(|h| h.to_str().ok().map(String::from)),
        roles: req.headers().get("x-user-roles").and_then(|h| h.to_str().ok().map(String::from)),
        permissions: req.headers().get("x-user-permissions").and_then(|h| h.to_str().ok().map(String::from)),
    };

    let info = RequestInfo {
        method,
        uri,
        host,
        headers,
        forwarded_headers,
        user_info,
    };

    axum::Json(info)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", any(handle_request))
        .route("/{*wildcard}", any(handle_request))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}
