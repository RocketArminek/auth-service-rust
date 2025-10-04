use uuid::Uuid;
use crate::domain::permission::Permission;
use crate::domain::repository::{RepositoryError};
use crate::domain::user::User;
use crate::infrastructure::database::DatabasePool;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;
use crate::infrastructure::sqlite_user_repository::SqliteUserRepository;

#[derive(Clone)]
pub enum UserRepository {
    Mysql(MysqlUserRepository),
    Sqlite(SqliteUserRepository)
}

impl UserRepository {
    pub fn new(pool: &DatabasePool) -> Self {
        match pool {
            DatabasePool::MySql(pool) => Self::Mysql(MysqlUserRepository::new(pool.clone())),
            DatabasePool::Sqlite(pool) => Self::Sqlite(SqliteUserRepository::new(pool.clone())),
        }
    }

    pub async fn save(&self, user: &User) -> Result<(), RepositoryError> {
        match self {
            UserRepository::Mysql(repo) => repo.save(user).await,
            UserRepository::Sqlite(repo) => repo.save(user).await,
        }
    }

    pub async fn get_by_id(&self, id: &Uuid) -> Result<User, RepositoryError> {
        match self {
            UserRepository::Mysql(repo) => repo.get_by_id(id).await,
            UserRepository::Sqlite(repo) => repo.get_by_id(id).await,
        }
    }
    
    pub async fn get_by_email(&self, email: &str) -> Result<User, RepositoryError> {
        match self {
            UserRepository::Mysql(repo) => repo.get_by_email(email).await,
            UserRepository::Sqlite(repo) => repo.get_by_email(email).await,
        }
    }
    
    pub async fn delete_by_email(&self, email: &str) -> Result<(), RepositoryError> {
        match self {
            UserRepository::Mysql(repo) => repo.delete_by_email(email).await,
            UserRepository::Sqlite(repo) => repo.delete_by_email(email).await,
        }
    }
    
    pub async fn find_all(&self, page: i32, limit: i32) -> Result<(Vec<User>, i32), RepositoryError> {
        match self {
            UserRepository::Mysql(repo) => repo.find_all(page, limit).await,
            UserRepository::Sqlite(repo) => repo.find_all(page, limit).await,
        }
    }
    
    pub async fn get_by_id_with_permissions(
        &self,
        id: &Uuid,
    ) -> Result<(User, Vec<Permission>), RepositoryError> {
        match self {
            UserRepository::Mysql(repo) => repo.get_by_id_with_permissions(id).await,
            UserRepository::Sqlite(repo) => repo.get_by_id_with_permissions(id).await,
        }
    }

    pub async fn get_by_email_with_permissions(
        &self,
        email: &str,
    ) -> Result<(User, Vec<Permission>), RepositoryError> {
        match self {
            UserRepository::Mysql(repo) => repo.get_by_email_with_permissions(email).await,
            UserRepository::Sqlite(repo) => repo.get_by_email_with_permissions(email).await,
        }
    }
}
