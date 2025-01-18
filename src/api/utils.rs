use crate::api::dto::MessageResponse;
use crate::application::auth_service::AuthError;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

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
