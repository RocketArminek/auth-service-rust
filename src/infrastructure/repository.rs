use crate::domain::repository::RepositoryError;
use sqlx::Error as SqlxError;

impl From<SqlxError> for RepositoryError {
    fn from(error: SqlxError) -> Self {
        match error {
            SqlxError::RowNotFound => RepositoryError::NotFound("Entity not found".to_string()),
            _ => RepositoryError::Database(error),
        }
    }
}
