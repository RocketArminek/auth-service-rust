use crate::domain::role::Role;
use crate::domain::session::Session;
use crate::domain::user::User;
use async_trait::async_trait;
use sqlx::Error as SqlxError;
use std::error::Error;
use std::fmt;
use uuid::Uuid;
use crate::domain::permission::Permission;

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
    async fn mark_as_system(&self, id: &Uuid) -> Result<(), RepositoryError>;
    async fn add_permission(&self, role_id: &Uuid, permission_id: &Uuid) -> Result<(), RepositoryError>;
    async fn remove_permission(&self, role_id: &Uuid, permission_id: &Uuid) -> Result<(), RepositoryError>;
    async fn get_permissions(&self, role_id: &Uuid) -> Result<Vec<Permission>, RepositoryError>;
    async fn get_permissions_for_roles(&self, role_ids: &[Uuid]) -> Result<Vec<Permission>, RepositoryError>;
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

#[async_trait]
pub trait PermissionRepository: Send + Sync {
    async fn save(&self, permission: &Permission) -> Result<(), RepositoryError>;
    async fn get_by_id(&self, id: &Uuid) -> Result<Permission, RepositoryError>;
    async fn get_by_name(&self, name: &str, group_name: &str) -> Result<Permission, RepositoryError>;
    async fn get_all(&self, offset: i32, limit: i32) -> Result<Vec<Permission>, RepositoryError>;
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
