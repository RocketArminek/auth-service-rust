// File: src/api/security_mw.rs

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    headers.insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap()
    );

    headers.insert(
        "X-Frame-Options",
        "DENY".parse().unwrap()
    );
    headers.insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap()
    );
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap()
    );

    response
}
