use axum::{async_trait, extract::FromRequestParts, http::header, http::request::Parts, http::StatusCode, Json};
use jsonwebtoken::{DecodingKey, Validation};
use uuid::Uuid;
use crate::api::dto::{LoggedInUser, MessageResponse};
use crate::api::{SecretAware};
use crate::domain::jwt::Claims;

#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

#[derive(Debug, Clone)]
pub struct StatelessUserWithRoles(pub LoggedInUser);

#[async_trait]
impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

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
                        MessageResponse{message: String::from("Missing bearer token")}
                    )))
                }
            }
            None => Err((StatusCode::UNAUTHORIZED, Json(
                MessageResponse{message: String::from("Authorization header is missing")}
            ))),
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for StatelessUserWithRoles
where
    S: SecretAware + Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let BearerToken(token) = BearerToken::from_request_parts(parts, state).await?;
        let decoded = jsonwebtoken::decode::<Claims>(
            &token,
            &DecodingKey::from_secret(state.get_secret().as_ref()),
            &Validation::default(),
        );

        match decoded {
            Ok(decoded_token) => {
                let user_id = decoded_token.claims.id.clone();
                let user_id = Uuid::parse_str(&user_id);
                if user_id.is_err() {
                    tracing::warn!("Invalid user id: {:?}", user_id.err());
                    return Err((StatusCode::UNAUTHORIZED, Json(
                        MessageResponse{message: String::from("Invalid user id")}
                    )));
                }
                let user_id = user_id.unwrap();

                Ok(StatelessUserWithRoles(
                    LoggedInUser { id: user_id, email: decoded_token.claims.email, roles: vec![] }
                ))
            }
            Err(error) => match error.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    tracing::info!("Invalid token: {:?}", error);
                    Err((StatusCode::UNAUTHORIZED, Json(
                        MessageResponse{message: String::from("Invalid token")}
                    )))
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    tracing::info!("Invalid signature: {:?}", error);
                    Err((StatusCode::UNAUTHORIZED, Json(
                        MessageResponse{message: String::from("Invalid signature")}
                    )))
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    tracing::info!("Expired token: {:?}", error);
                    Err((StatusCode::UNAUTHORIZED, Json(
                        MessageResponse{message: String::from("Expired token")}
                    )))
                }
                _ => {
                    tracing::info!("Unknown error: {:?}", error);
                    Err((StatusCode::UNAUTHORIZED, Json(
                        MessageResponse{message: String::from("Unknown error")}
                    )))
                }
            }
        }
    }
}
