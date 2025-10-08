use crate::domain::permission::Permission;
use crate::domain::role::Role;
use crate::domain::user::User;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow, Debug, Clone)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_path: Option<String>,
    pub is_verified: bool,
}

#[derive(sqlx::FromRow)]
pub struct UserWithRoleRow {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_path: Option<String>,
    pub is_verified: bool,
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    pub role_created_at: Option<DateTime<Utc>>,
}

impl From<&UserWithRoleRow> for User {
    fn from(row: &UserWithRoleRow) -> Self {
        User {
            id: row.id,
            email: row.email.clone(),
            not_hashed_password: "".to_string(),
            password: row.password.clone(),
            first_name: row.first_name.clone(),
            last_name: row.last_name.clone(),
            created_at: row.created_at,
            avatar_path: row.avatar_path.clone(),
            is_verified: row.is_verified,
            roles: Vec::new(),
        }
    }
}

impl UserWithRoleRow {
    pub fn extract_role(&self) -> Option<Role> {
        self.role_id.map(|role_id| Role {
            id: role_id,
            name: self.role_name.clone().unwrap_or_default(),
            created_at: self.role_created_at.unwrap_or(self.created_at),
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct SessionWithUserRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub user_email: String,
    pub user_password: String,
    pub user_created_at: DateTime<Utc>,
    pub user_first_name: Option<String>,
    pub user_last_name: Option<String>,
    pub user_avatar_path: Option<String>,
    pub user_is_verified: bool,
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    pub role_created_at: Option<DateTime<Utc>>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        User {
            id: row.id,
            email: row.email,
            not_hashed_password: "".to_string(),
            password: row.password,
            first_name: row.first_name,
            last_name: row.last_name,
            created_at: row.created_at,
            roles: vec![],
            avatar_path: row.avatar_path,
            is_verified: row.is_verified,
        }
    }
}

#[derive(sqlx::FromRow)]
pub struct RoleWithPermissionsRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub is_system: bool,
    pub permission_id: Option<Uuid>,
    pub permission_name: Option<String>,
    pub permission_group_name: Option<String>,
    pub permission_description: Option<String>,
    pub permission_is_system: Option<bool>,
    pub permission_created_at: Option<DateTime<Utc>>,
}

impl RoleWithPermissionsRow {
    pub fn into_role_and_permission(self) -> (Role, Option<Permission>) {
        let role = Role {
            id: self.id,
            name: self.name,
            created_at: self.created_at,
        };

        let permission =
            if let (Some(id), Some(name), Some(group_name), Some(is_system), Some(created_at)) = (
                self.permission_id,
                self.permission_name,
                self.permission_group_name,
                self.permission_is_system,
                self.permission_created_at,
            ) {
                Some(Permission {
                    id,
                    name,
                    group_name,
                    description: self.permission_description,
                    is_system,
                    created_at,
                })
            } else {
                None
            };

        (role, permission)
    }
}

#[derive(sqlx::FromRow)]
pub struct UserWithPermissionsRow {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_path: Option<String>,
    pub is_verified: bool,
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    pub role_created_at: Option<DateTime<Utc>>,
    pub permission_id: Option<Uuid>,
    pub permission_name: Option<String>,
    pub permission_group_name: Option<String>,
    pub permission_description: Option<String>,
    pub permission_is_system: Option<bool>,
    pub permission_created_at: Option<DateTime<Utc>>,
}

impl From<&UserWithPermissionsRow> for User {
    fn from(row: &UserWithPermissionsRow) -> Self {
        User {
            id: row.id,
            email: row.email.clone(),
            not_hashed_password: "".to_string(),
            password: row.password.clone(),
            first_name: row.first_name.clone(),
            last_name: row.last_name.clone(),
            created_at: row.created_at,
            avatar_path: row.avatar_path.clone(),
            is_verified: row.is_verified,
            roles: Vec::new(),
        }
    }
}

impl UserWithPermissionsRow {
    pub fn extract_role(&self) -> Option<Role> {
        self.role_id.map(|role_id| Role {
            id: role_id,
            name: self.role_name.clone().unwrap_or_default(),
            created_at: self.role_created_at.unwrap_or(self.created_at),
        })
    }

    pub fn extract_permission(&self) -> Option<Permission> {
        self.permission_id.map(|permission_id| Permission {
            id: permission_id,
            name: self.permission_name.clone().unwrap_or_default(),
            group_name: self.permission_group_name.clone().unwrap_or_default(),
            description: self.permission_description.clone(),
            created_at: self.permission_created_at.unwrap_or(self.created_at),
            is_system: self.permission_is_system.unwrap_or(false),
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct SessionWithUserAndPermissionsRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub user_email: String,
    pub user_password: String,
    pub user_created_at: DateTime<Utc>,
    pub user_first_name: Option<String>,
    pub user_last_name: Option<String>,
    pub user_avatar_path: Option<String>,
    pub user_is_verified: bool,
    pub role_id: Option<Uuid>,
    pub role_name: Option<String>,
    pub role_created_at: Option<DateTime<Utc>>,
    pub permission_id: Option<Uuid>,
    pub permission_name: Option<String>,
    pub permission_group_name: Option<String>,
    pub permission_description: Option<String>,
    pub permission_is_system: Option<bool>,
    pub permission_created_at: Option<DateTime<Utc>>,
}
