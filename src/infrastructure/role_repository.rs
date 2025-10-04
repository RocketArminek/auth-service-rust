use crate::domain::permission::Permission;
use crate::domain::repository::RepositoryError;
use crate::domain::role::Role;
use crate::infrastructure::database::DatabasePool;
use crate::infrastructure::mysql_role_repository::MysqlRoleRepository;
use crate::infrastructure::sqlite_role_repository::SqliteRoleRepository;
use uuid::Uuid;

#[derive(Clone)]
pub enum RoleRepository {
    Mysql(MysqlRoleRepository),
    Sqlite(SqliteRoleRepository),
}

impl RoleRepository {
    pub fn new(pool: &DatabasePool) -> Self {
        match pool {
            DatabasePool::MySql(pool) => Self::Mysql(MysqlRoleRepository::new(pool.clone())),
            DatabasePool::Sqlite(pool) => Self::Sqlite(SqliteRoleRepository::new(pool.clone())),
        }
    }

    pub async fn save(&self, role: &Role) -> Result<(), RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.save(role).await,
            RoleRepository::Sqlite(repo) => repo.save(role).await,
        }
    }

    pub async fn get_by_id(&self, id: &Uuid) -> Result<Role, RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.get_by_id(id).await,
            RoleRepository::Sqlite(repo) => repo.get_by_id(id).await,
        }
    }

    pub async fn get_by_id_with_permissions(
        &self,
        role_id: &Uuid,
    ) -> Result<(Role, Vec<Permission>), RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.get_by_id_with_permissions(role_id).await,
            RoleRepository::Sqlite(repo) => repo.get_by_id_with_permissions(role_id).await,
        }
    }

    pub async fn get_by_name(&self, name: &str) -> Result<Role, RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.get_by_name(name).await,
            RoleRepository::Sqlite(repo) => repo.get_by_name(name).await,
        }
    }

    pub async fn get_by_name_with_permissions(
        &self,
        name: &str,
    ) -> Result<(Role, Vec<Permission>), RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.get_by_name_with_permissions(name).await,
            RoleRepository::Sqlite(repo) => repo.get_by_name_with_permissions(name).await,
        }
    }

    pub async fn get_all(&self, page: i32, limit: i32) -> Result<Vec<Role>, RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.get_all(page, limit).await,
            RoleRepository::Sqlite(repo) => repo.get_all(page, limit).await,
        }
    }

    pub async fn get_all_with_permissions(
        &self,
        page: i32,
        limit: i32,
    ) -> Result<Vec<(Role, Vec<Permission>)>, RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.get_all_with_permissions(page, limit).await,
            RoleRepository::Sqlite(repo) => repo.get_all_with_permissions(page, limit).await,
        }
    }

    pub async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.delete(id).await,
            RoleRepository::Sqlite(repo) => repo.delete(id).await,
        }
    }

    pub async fn delete_by_name(&self, name: &str) -> Result<(), RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.delete_by_name(name).await,
            RoleRepository::Sqlite(repo) => repo.delete_by_name(name).await,
        }
    }

    pub async fn mark_as_system(&self, id: &Uuid) -> Result<(), RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.mark_as_system(id).await,
            RoleRepository::Sqlite(repo) => repo.mark_as_system(id).await,
        }
    }

    pub async fn add_permission(
        &self,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<(), RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.add_permission(role_id, permission_id).await,
            RoleRepository::Sqlite(repo) => repo.add_permission(role_id, permission_id).await,
        }
    }

    pub async fn remove_permission(
        &self,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<(), RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.remove_permission(role_id, permission_id).await,
            RoleRepository::Sqlite(repo) => repo.remove_permission(role_id, permission_id).await,
        }
    }

    pub async fn get_permissions(
        &self,
        role_id: &Uuid,
    ) -> Result<Vec<Permission>, RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.get_permissions(role_id).await,
            RoleRepository::Sqlite(repo) => repo.get_permissions(role_id).await,
        }
    }

    pub async fn get_permissions_for_roles(
        &self,
        role_ids: &[Uuid],
    ) -> Result<Vec<Permission>, RepositoryError> {
        match self {
            RoleRepository::Mysql(repo) => repo.get_permissions_for_roles(role_ids).await,
            RoleRepository::Sqlite(repo) => repo.get_permissions_for_roles(role_ids).await,
        }
    }
}
