use crate::api::dto::MessageResponse;
use crate::domain::repositories::{RoleRepository, UserRepository, SessionRepository};
use crate::infrastructure::database::DatabasePool;
use crate::infrastructure::mysql_role_repository::MysqlRoleRepository;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;
use crate::infrastructure::sqlite_role_repository::SqliteRoleRepository;
use crate::infrastructure::sqlite_user_repository::SqliteUserRepository;
use crate::infrastructure::mysql_session_repository::MysqlSessionRepository;
use crate::infrastructure::sqlite_session_repository::SqliteSessionRepository;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sqlx::Error as SqlxError;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use tokio::sync::Mutex;

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

pub fn create_user_repository(pool: DatabasePool) -> Arc<Mutex<dyn UserRepository>> {
    match pool {
        DatabasePool::MySql(pool) => Arc::new(Mutex::new(MysqlUserRepository::new(pool))),
        DatabasePool::Sqlite(pool) => Arc::new(Mutex::new(SqliteUserRepository::new(pool))),
    }
}

pub fn create_role_repository(pool: DatabasePool) -> Arc<Mutex<dyn RoleRepository>> {
    match pool {
        DatabasePool::MySql(pool) => Arc::new(Mutex::new(MysqlRoleRepository::new(pool))),
        DatabasePool::Sqlite(pool) => Arc::new(Mutex::new(SqliteRoleRepository::new(pool))),
    }
}

pub fn create_session_repository(pool: DatabasePool) -> Arc<Mutex<dyn SessionRepository>> {
    match pool {
        DatabasePool::MySql(pool) => Arc::new(Mutex::new(MysqlSessionRepository::new(pool))),
        DatabasePool::Sqlite(pool) => Arc::new(Mutex::new(SqliteSessionRepository::new(pool))),
    }
}
