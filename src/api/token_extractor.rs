use axum::{async_trait, extract::FromRequestParts, http::header, http::request::Parts, http::StatusCode, Json};
use crate::api::user_controller::{AuthResponse, MessageResponse};

#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

#[async_trait]
impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<AuthResponse>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let headers = parts.headers.clone();
        match headers.get(header::AUTHORIZATION) {
            Some(value) => {
                let value = value.to_str().unwrap_or("");
                if value.starts_with("Bearer ") {
                    Ok(BearerToken(value[7..].to_string()))
                } else {
                    tracing::warn!("Invalid Authorization header: {}", value);

                    Err((StatusCode::UNAUTHORIZED, Json(
                        AuthResponse::Unauthorized(MessageResponse{
                            message: String::from("Missing bearer token"),
                        })
                    )))
                }
            }
            None => Err((StatusCode::UNAUTHORIZED, Json(
                AuthResponse::Unauthorized(MessageResponse{
                    message: String::from("Authorization header is missing"),
                })
            ))),
        }
    }
}
