use crate::domain::permission::Permission;
use crate::infrastructure::database::DatabasePool;
use crate::infrastructure::mysql_permission_repository::MysqlPermissionRepository;
use crate::infrastructure::repository::RepositoryError;
use crate::infrastructure::sqlite_permission_repository::SqlitePermissionRepository;
use uuid::Uuid;

#[derive(Clone)]
pub enum PermissionRepository {
    Mysql(MysqlPermissionRepository),
    Sqlite(SqlitePermissionRepository),
}

impl PermissionRepository {
    pub fn new(pool: &DatabasePool) -> Self {
        match pool {
            DatabasePool::MySql(pool) => Self::Mysql(MysqlPermissionRepository::new(pool.clone())),
            DatabasePool::Sqlite(pool) => {
                Self::Sqlite(SqlitePermissionRepository::new(pool.clone()))
            }
        }
    }

    pub async fn save(&self, permission: &Permission) -> Result<(), RepositoryError> {
        match self {
            PermissionRepository::Mysql(repo) => repo.save(permission).await,
            PermissionRepository::Sqlite(repo) => repo.save(permission).await,
        }
    }

    pub async fn get_by_name(
        &self,
        name: &str,
        group_name: &str,
    ) -> Result<Permission, RepositoryError> {
        match self {
            PermissionRepository::Mysql(repo) => repo.get_by_name(name, group_name).await,
            PermissionRepository::Sqlite(repo) => repo.get_by_name(name, group_name).await,
        }
    }

    pub async fn get_by_id(&self, id: &Uuid) -> Result<Permission, RepositoryError> {
        match self {
            PermissionRepository::Mysql(repo) => repo.get_by_id(id).await,
            PermissionRepository::Sqlite(repo) => repo.get_by_id(id).await,
        }
    }

    pub async fn get_all(&self, page: i32, limit: i32) -> Result<Vec<Permission>, RepositoryError> {
        match self {
            PermissionRepository::Mysql(repo) => repo.get_all(page, limit).await,
            PermissionRepository::Sqlite(repo) => repo.get_all(page, limit).await,
        }
    }

    pub async fn get_by_group(&self, group_name: &str) -> Result<Vec<Permission>, RepositoryError> {
        match self {
            PermissionRepository::Mysql(repo) => repo.get_by_group(group_name).await,
            PermissionRepository::Sqlite(repo) => repo.get_by_group(group_name).await,
        }
    }

    pub async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError> {
        match self {
            PermissionRepository::Mysql(repo) => repo.delete(id).await,
            PermissionRepository::Sqlite(repo) => repo.delete(id).await,
        }
    }

    pub async fn mark_as_system(&self, id: &Uuid) -> Result<(), RepositoryError> {
        match self {
            PermissionRepository::Mysql(repo) => repo.mark_as_system(id).await,
            PermissionRepository::Sqlite(repo) => repo.mark_as_system(id).await,
        }
    }
}
