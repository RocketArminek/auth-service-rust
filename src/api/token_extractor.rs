use axum::{
    async_trait, extract::FromRequestParts, http::header, http::request::Parts, http::StatusCode,
};

#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

#[async_trait]
impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let headers = parts.headers.clone();
        match headers.get(header::AUTHORIZATION) {
            Some(value) => {
                let value = value.to_str().unwrap();
                if value.starts_with("Bearer ") {
                    Ok(BearerToken(value[7..].to_string()))
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            }
            None => Err(StatusCode::UNAUTHORIZED),
        }
    }
}
