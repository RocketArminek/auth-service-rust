use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::{extract::Request, middleware::Next, response::Response};

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());

    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    
    headers.insert("Cross-Origin-Opener-Policy", "same-origin".parse().unwrap());
    headers.insert("Cross-Origin-Embedder-Policy", "require-corp".parse().unwrap());
    headers.insert("Cross-Origin-Resource-Policy", "same-origin".parse().unwrap());

    response
}

pub async fn restrict_methods(req: Request, next: Next) -> Response {
    match *req.method() {
        Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE => {
            next.run(req).await
        }
        Method::OPTIONS => Response::builder()
            .status(StatusCode::OK)
            .header("Allow", "GET, POST, PUT, PATCH, DELETE")
            .body(axum::body::Body::empty())
            .unwrap(),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}
