use crate::api::dto::MessageResponse;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sqlx::Error as SqlxError;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum RepositoryError {
    NotFound(String),
    Database(SqlxError),
    Conflict(String),
    ValidationError(String),
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepositoryError::NotFound(msg) => write!(f, "{}", msg),
            RepositoryError::Database(e) => write!(f, "Database error: {}", e),
            RepositoryError::Conflict(msg) => write!(f, "Conflict error: {}", msg),
            RepositoryError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl Error for RepositoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RepositoryError::Database(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SqlxError> for RepositoryError {
    fn from(error: SqlxError) -> Self {
        match error {
            SqlxError::RowNotFound => RepositoryError::NotFound("Entity not found".to_string()),
            _ => RepositoryError::Database(error),
        }
    }
}

impl IntoResponse for RepositoryError {
    fn into_response(self) -> axum::response::Response {
        match self {
            RepositoryError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                Json(MessageResponse { message: msg }),
            )
                .into_response(),
            RepositoryError::Conflict(msg) => {
                (StatusCode::CONFLICT, Json(MessageResponse { message: msg })).into_response()
            }
            RepositoryError::ValidationError(msg) => (
                StatusCode::BAD_REQUEST,
                Json(MessageResponse { message: msg }),
            )
                .into_response(),
            RepositoryError::Database(e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(MessageResponse {
                        message: "Internal server error".to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}
