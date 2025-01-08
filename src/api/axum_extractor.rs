use crate::api::dto::MessageResponse;
use crate::api::server_state::{SecretAware, VerificationRequired};
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use axum::{
    extract::FromRequestParts, http::header, http::request::Parts, http::StatusCode,
    Json,
};
use jsonwebtoken::{DecodingKey, Validation};

#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

#[derive(Debug, Clone)]
pub struct StatelessLoggedInUser(pub UserDTO);

#[derive(Debug, Clone)]
pub struct RefreshRequest(pub UserDTO);

#[derive(Debug, Clone)]
pub struct VerificationRequest(pub UserDTO);

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

impl<S> FromRequestParts<S> for StatelessLoggedInUser
where
    S: SecretAware + VerificationRequired + Send + Sync,
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
                    TokenType::Access => {
                        if state.get_verification_required() {
                            if !decoded_token.claims.user.is_verified {
                                return Err((
                                    StatusCode::UNAUTHORIZED,
                                    Json(MessageResponse {
                                        message: String::from("User is not verified!"),
                                    }),
                                ));
                            }
                        }
                        Ok(StatelessLoggedInUser(decoded_token.claims.user))
                    }
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

impl<S> FromRequestParts<S> for RefreshRequest
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
                    TokenType::Refresh => Ok(RefreshRequest(decoded_token.claims.user)),
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

impl<S> FromRequestParts<S> for VerificationRequest
where
    S: SecretAware + VerificationRequired + Send + Sync,
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
                    TokenType::Verification => Ok(VerificationRequest(decoded_token.claims.user)),
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
