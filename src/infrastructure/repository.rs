use crate::domain::repository::{
    PermissionRepository, RepositoryError, RoleRepository,
};
use crate::infrastructure::database::DatabasePool;
use crate::infrastructure::mysql_permission_repository::MysqlPermissionRepository;
use crate::infrastructure::mysql_role_repository::MysqlRoleRepository;
use crate::infrastructure::sqlite_permission_repository::SqlitePermissionRepository;
use crate::infrastructure::sqlite_role_repository::SqliteRoleRepository;
use sqlx::Error as SqlxError;
use std::sync::Arc;

pub fn create_role_repository(pool: DatabasePool) -> Arc<dyn RoleRepository> {
    match pool {
        DatabasePool::MySql(pool) => Arc::new(MysqlRoleRepository::new(pool)),
        DatabasePool::Sqlite(pool) => Arc::new(SqliteRoleRepository::new(pool)),
    }
}

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
