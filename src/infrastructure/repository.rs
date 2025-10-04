use crate::domain::repository::{PermissionRepository, RepositoryError};
use crate::infrastructure::database::DatabasePool;
use crate::infrastructure::mysql_permission_repository::MysqlPermissionRepository;
use crate::infrastructure::sqlite_permission_repository::SqlitePermissionRepository;
use sqlx::Error as SqlxError;
use std::sync::Arc;

pub fn create_permission_repository(pool: DatabasePool) -> Arc<dyn PermissionRepository> {
    match pool {
        DatabasePool::MySql(pool) => Arc::new(MysqlPermissionRepository::new(pool)),
        DatabasePool::Sqlite(pool) => Arc::new(SqlitePermissionRepository::new(pool)),
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
