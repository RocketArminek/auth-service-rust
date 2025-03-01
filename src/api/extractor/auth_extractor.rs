use crate::api::dto::MessageResponse;
use crate::api::server_state::{AuthServiceAware, SecretAware};
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use axum::{Json, extract::FromRequestParts, http::StatusCode, http::header, http::request::Parts};
use jsonwebtoken::{DecodingKey, Validation};

#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

#[derive(Debug, Clone)]
pub struct LoggedInUser(pub UserDTO);

#[derive(Debug, Clone)]
pub struct PasswordToken(pub UserDTO);

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
                if let Some(token) = value.strip_prefix("Bearer ") {
                    Ok(BearerToken(token.to_string()))
                } else {
                    tracing::warn!("Invalid Authorization header: {}", value);

                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(MessageResponse {
                            message: String::from("Missing bearer token"),
                        }),
                    ))
                }
            }
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: String::from("Authorization header is missing"),
                }),
            )),
        }
    }
}

impl<S> FromRequestParts<S> for LoggedInUser
where
    S: SecretAware + AuthServiceAware + Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let BearerToken(token) = BearerToken::from_request_parts(parts, state).await?;

        let result = state.get_auth_service().authenticate(token).await;

        result
            .map(LoggedInUser)
            .map_err(|e| e.into_message_response())
    }
}

impl<S> FromRequestParts<S> for PasswordToken
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
                tracing::debug!("Decoded token: {:?}", decoded_token.claims);
                match decoded_token.claims.token_type {
                    TokenType::Password => Ok(PasswordToken(decoded_token.claims.user)),
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
