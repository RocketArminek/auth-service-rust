use crate::api::dto::MessageResponse;
use crate::api::server_state::{AuthServiceAware, TokenServiceAware};
use crate::application::service::token_service::{PasswordReset, TokenError};
use crate::domain::jwt::UserDTO;
use axum::{Json, extract::FromRequestParts, http::StatusCode, http::header, http::request::Parts};

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
    S: AuthServiceAware + Send + Sync,
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
    S: TokenServiceAware + Send + Sync,
{
    type Rejection = (StatusCode, Json<MessageResponse>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let BearerToken(token) = BearerToken::from_request_parts(parts, state).await?;

        match state.get_token_service().validate::<PasswordReset>(&token) {
            Ok(claims) => Ok(PasswordToken(claims.into_user())),
            Err(error) => {
                tracing::debug!("Password token rejected: {:?}", error);
                let message = match error {
                    TokenError::WrongKind => "Invalid token type",
                    TokenError::Expired => "Expired token",
                    TokenError::InvalidSignature => "Invalid signature",
                    TokenError::Malformed => "Invalid token",
                    _ => "Unknown error",
                };

                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(MessageResponse {
                        message: String::from(message),
                    }),
                ))
            }
        }
    }
}
