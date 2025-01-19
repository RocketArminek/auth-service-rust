use crate::api::dto::{LoginResponse, MessageResponse, TokenResponse};
use crate::application::service::auth_service::{AuthError, TokenPair};
use crate::domain::jwt::UserDTO;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

pub trait IntoAuthResponse {
    fn into_auth_response(self) -> axum::response::Response;
}

impl IntoAuthResponse for Result<(TokenPair, UserDTO), AuthError> {
    fn into_auth_response(self) -> axum::response::Response {
        match self {
            Ok((tokens, user)) => Json(LoginResponse {
                user,
                refresh_token: TokenResponse {
                    value: tokens.refresh_token.value,
                    expires_at: tokens.refresh_token.expires_at,
                },
                access_token: TokenResponse {
                    value: tokens.access_token.value,
                    expires_at: tokens.access_token.expires_at,
                },
            })
            .into_response(),
            Err(e) => e.into_response(),
        }
    }
}

impl IntoAuthResponse for Result<(), AuthError> {
    fn into_auth_response(self) -> axum::response::Response {
        match self {
            Ok(_) => StatusCode::OK.into_response(),
            Err(e) => e.into_response(),
        }
    }
}

impl AuthError {
    pub fn into_message_response(self) -> (StatusCode, Json<MessageResponse>) {
        match self {
            AuthError::UserNotFound => (
                StatusCode::NOT_FOUND,
                Json(MessageResponse {
                    message: "User not found".to_string(),
                }),
            ),
            AuthError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Expired token".to_string(),
                }),
            ),
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Invalid credentials".to_string(),
                }),
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Invalid token".to_string(),
                }),
            ),
            AuthError::InvalidTokenType => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Invalid token type".to_string(),
                }),
            ),
            AuthError::InternalError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MessageResponse {
                    message: "Internal error".to_string(),
                }),
            ),
            AuthError::TokenEncodingFailed => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Token encoding failed".to_string(),
                }),
            ),
            AuthError::SessionNotFound => (
                StatusCode::UNAUTHORIZED,
                Json(MessageResponse {
                    message: "Session not found".to_string(),
                }),
            ),
            AuthError::AuthStrategyNotSupported => (
                StatusCode::BAD_REQUEST,
                Json(MessageResponse {
                    message: "Action not supported in this strategy".to_string(),
                }),
            ),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        self.into_message_response().into_response()
    }
}
