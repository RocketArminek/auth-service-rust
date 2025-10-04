use sqlx::Error as SqlxError;
use std::error::Error;
use std::fmt;

impl From<SqlxError> for RepositoryError {
    fn from(error: SqlxError) -> Self {
        match error {
            SqlxError::RowNotFound => RepositoryError::NotFound("Entity not found".to_string()),
            _ => RepositoryError::Database(error),
        }
    }
}

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
