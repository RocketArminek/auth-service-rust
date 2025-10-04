use crate::domain::permission::Permission;
use async_trait::async_trait;
use sqlx::Error as SqlxError;
use std::error::Error;
use std::fmt;
use uuid::Uuid;

#[async_trait]
pub trait PermissionRepository: Send + Sync {
    async fn save(&self, permission: &Permission) -> Result<(), RepositoryError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Permission, RepositoryError>;
    async fn get_by_name(
        &self,
        name: &str,
        group_name: &str,
    ) -> Result<Permission, RepositoryError>;
    async fn get_all(&self, page: i32, limit: i32) -> Result<Vec<Permission>, RepositoryError>;
    async fn get_by_group(&self, group_name: &str) -> Result<Vec<Permission>, RepositoryError>;
    async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError>;
    async fn mark_as_system(&self, id: &Uuid) -> Result<(), RepositoryError>;
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
