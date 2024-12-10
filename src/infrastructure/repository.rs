use std::error::Error;
use std::fmt;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use sqlx::Error as SqlxError;
use crate::api::dto::MessageResponse;

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
            RepositoryError::NotFound(msg) => write!(f, "Entity not found: {}", msg),
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
            _ => RepositoryError::Database(error)
        }
    }
}

impl IntoResponse for RepositoryError {
    fn into_response(self) -> axum::response::Response {
        map_repository_error(self).into_response()
    }
}

pub fn map_repository_error(error: RepositoryError) -> (StatusCode, Json<MessageResponse>) {
    match error {
        RepositoryError::NotFound(msg) => (
            StatusCode::NOT_FOUND,
            Json(MessageResponse { message: msg }),
        ),
        RepositoryError::Conflict(msg) => (
            StatusCode::CONFLICT,
            Json(MessageResponse { message: msg }),
        ),
        RepositoryError::ValidationError(msg) => (
            StatusCode::BAD_REQUEST,
            Json(MessageResponse { message: msg }),
        ),
        RepositoryError::Database(e) => {
            tracing::error!("Database error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MessageResponse {
                    message: "Internal server error".to_string(),
                }),
            )
        }
    }
}
