use axum::async_trait;
use sqlx::Error;
use uuid::Uuid;
use crate::domain::role::Role;
use crate::domain::user::User;
use crate::infrastructure::repository::RepositoryError;

#[async_trait]
pub trait UserRepository {
    async fn save(&self, user: &User) -> Result<(), RepositoryError>;
    async fn get_by_id(&self, id: Uuid) -> Result<User, RepositoryError>;
    async fn get_by_email(&self, email: &String) -> Result<User, RepositoryError>;
    async fn delete_by_email(&self, email: &String) -> Result<(), Error>;
    async fn find_all(&self, page: i32, limit: i32) -> Result<(Vec<User>, i32), RepositoryError>;
}

#[async_trait]
pub trait RoleRepository {
    async fn save(&self, role: &Role) -> Result<(), RepositoryError>;
    async fn get_by_id(&self, id: Uuid) -> Result<Role, RepositoryError>;
    async fn get_by_name(&self, name: &String) -> Result<Role, RepositoryError>;
    async fn get_all(&self) -> Result<Vec<Role>, RepositoryError>;
    async fn delete(&self, id: Uuid) -> Result<(), RepositoryError>;
    async fn delete_by_name(&self, name: &String) -> Result<(), RepositoryError>;
}
