use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use jsonwebtoken::{DecodingKey, Validation};
use crate::api::axum_extractor::BearerToken;
use crate::api::dto::MessageResponse;
use crate::api::server_state::{SecretAware, SessionRepositoryAware, UserRepositoryAware};
use crate::domain::jwt::{StatefulClaims, TokenType, UserDTO};
use crate::domain::session::Session;

#[derive(Debug, Clone)]
pub struct LoggedInUser { pub user: UserDTO, pub session: Session }

#[derive(Debug, Clone)]
pub struct RefreshToken{ pub user: UserDTO, pub session: Session }

impl<S> FromRequestParts<S> for LoggedInUser
where
    S: SecretAware + SessionRepositoryAware + UserRepositoryAware + Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let BearerToken(token) = BearerToken::from_request_parts(parts, state).await?;
        let decoded = jsonwebtoken::decode::<StatefulClaims>(
            &token,
            &DecodingKey::from_secret(state.get_secret().as_ref()),
            &Validation::default(),
        );

        match decoded {
            Ok(decoded_token) => {
                tracing::debug!("Decoded token: {:?}", decoded_token.claims);
                match decoded_token.claims.token_type {
                    TokenType::Access => {
                        let (session, user) = state
                            .get_session_repository()
                            .lock()
                            .await
                            .get_session_with_user(&decoded_token.claims.session_id)
                            .await
                            .map_err(|_| {
                                (
                                    StatusCode::UNAUTHORIZED,
                                    Json(MessageResponse {
                                        message: String::from("Invalid session"),
                                    }),
                                )
                            })?;

                        if session.is_expired() {
                            return Err((
                                StatusCode::UNAUTHORIZED,
                                Json(MessageResponse {
                                    message: String::from("Session expired"),
                                }),
                            ));
                        }

                        Ok(LoggedInUser {
                            user: UserDTO::from(user),
                            session,
                        })
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

impl<S> FromRequestParts<S> for RefreshToken
where
    S: SecretAware + SessionRepositoryAware + UserRepositoryAware + Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let BearerToken(token) = BearerToken::from_request_parts(parts, state).await?;
        let decoded = jsonwebtoken::decode::<StatefulClaims>(
            &token,
            &DecodingKey::from_secret(state.get_secret().as_ref()),
            &Validation::default(),
        );

        match decoded {
            Ok(decoded_token) => {
                tracing::debug!("Decoded token: {:?}", decoded_token.claims);
                match decoded_token.claims.token_type {
                    TokenType::Refresh => {
                        let (session, user) = state
                            .get_session_repository()
                            .lock()
                            .await
                            .get_session_with_user(&decoded_token.claims.session_id)
                            .await
                            .map_err(|_| {
                                (
                                    StatusCode::UNAUTHORIZED,
                                    Json(MessageResponse {
                                        message: String::from("Invalid session"),
                                    }),
                                )
                            })?;

                        if session.is_expired() {
                            return Err((
                                StatusCode::UNAUTHORIZED,
                                Json(MessageResponse {
                                    message: String::from("Session expired"),
                                }),
                            ));
                        }

                        Ok(RefreshToken{user: UserDTO::from(user), session})
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
