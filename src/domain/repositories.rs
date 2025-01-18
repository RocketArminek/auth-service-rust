use crate::domain::role::Role;
use crate::domain::session::Session;
use crate::domain::user::User;
use crate::infrastructure::repository::RepositoryError;
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn save(&self, user: &User) -> Result<(), RepositoryError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<User, RepositoryError>;
    async fn get_by_email(&self, email: &str) -> Result<User, RepositoryError>;
    async fn delete_by_email(&self, email: &str) -> Result<(), RepositoryError>;
    async fn find_all(&self, page: i32, limit: i32) -> Result<(Vec<User>, i32), RepositoryError>;
}

#[async_trait]
pub trait RoleRepository: Send + Sync {
    async fn save(&self, role: &Role) -> Result<(), RepositoryError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Role, RepositoryError>;
    async fn get_by_name(&self, name: &str) -> Result<Role, RepositoryError>;
    async fn get_all(&self, offset: i32, limit: i32) -> Result<Vec<Role>, RepositoryError>;
    async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError>;
    async fn delete_by_name(&self, name: &str) -> Result<(), RepositoryError>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn save(&self, session: &Session) -> Result<(), RepositoryError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Session, RepositoryError>;
    async fn get_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Session>, RepositoryError>;
    async fn get_all(&self, page: i32, limit: i32) -> Result<(Vec<Session>, i32), RepositoryError>;
    async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError>;
    async fn delete_all_by_user_id(&self, user_id: &Uuid) -> Result<(), RepositoryError>;
    async fn get_session_with_user(&self, id: &Uuid) -> Result<(Session, User), RepositoryError>;
    async fn delete_expired(&self) -> Result<(), RepositoryError>;
}
