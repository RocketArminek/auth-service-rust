use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use jsonwebtoken::{DecodingKey, Validation};
use crate::api::axum_extractor::BearerToken;
use crate::api::dto::MessageResponse;
use crate::api::server_state::{SecretAware};
use crate::domain::jwt::{StatelessClaims, TokenType, UserDTO};

#[derive(Debug, Clone)]
pub struct LoggedInUser(pub UserDTO);

#[derive(Debug, Clone)]
pub struct RefreshToken(pub UserDTO);

impl<S> FromRequestParts<S> for LoggedInUser
where
    S: SecretAware + Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let BearerToken(token) = BearerToken::from_request_parts(parts, state).await?;
        let decoded = jsonwebtoken::decode::<StatelessClaims>(
            &token,
            &DecodingKey::from_secret(state.get_secret().as_ref()),
            &Validation::default(),
        );

        match decoded {
            Ok(decoded_token) => {
                tracing::debug!("Decoded token: {:?}", decoded_token.claims);
                match decoded_token.claims.token_type {
                    TokenType::Access => Ok(LoggedInUser(decoded_token.claims.user)),
                    _ => Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Invalid token type"),
                        }),
                    )),
                }
            }
            Err(error) => match error.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    tracing::debug!("Invalid token: {:?}", error);
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Invalid token"),
                        }),
                    ))
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    tracing::debug!("Invalid signature: {:?}", error);
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Invalid signature"),
                        }),
                    ))
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    tracing::debug!("Expired token: {:?}", error);
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Expired token"),
                        }),
                    ))
                }
                _ => {
                    tracing::warn!("Unknown error: {:?}", error);
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Unknown error"),
                        }),
                    ))
                }
            },
        }
    }
}

impl<S> FromRequestParts<S> for RefreshToken
where
    S: SecretAware + Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let BearerToken(token) = BearerToken::from_request_parts(parts, state).await?;
        let decoded = jsonwebtoken::decode::<StatelessClaims>(
            &token,
            &DecodingKey::from_secret(state.get_secret().as_ref()),
            &Validation::default(),
        );

        match decoded {
            Ok(decoded_token) => {
                tracing::debug!("Decoded token: {:?}", decoded_token.claims);
                match decoded_token.claims.token_type {
                    TokenType::Refresh => Ok(RefreshToken(decoded_token.claims.user)),
                    _ => Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Invalid token type"),
                        }),
                    )),
                }
            }
            Err(error) => match error.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    tracing::debug!("Invalid token: {:?}", error);
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Invalid token"),
                        }),
                    ))
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    tracing::debug!("Invalid signature: {:?}", error);
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Invalid signature"),
                        }),
                    ))
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    tracing::debug!("Expired token: {:?}", error);
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Expired token"),
                        }),
                    ))
                }
                _ => {
                    tracing::warn!("Unknown error: {:?}", error);
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Unknown error"),
                        }),
                    ))
                }
            },
        }
    }
}
