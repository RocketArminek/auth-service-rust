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

#[derive(FromRow, Debug, Clone)]
pub struct SessionWithUserRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[sqlx(rename = "user.id")]
    pub user_id_alias: Uuid,
    #[sqlx(rename = "user.email")]
    pub user_email: String,
    #[sqlx(rename = "user.password")]
    pub user_password: String,
    #[sqlx(rename = "user.created_at")]
    pub user_created_at: DateTime<Utc>,
    #[sqlx(rename = "user.first_name")]
    pub user_first_name: Option<String>,
    #[sqlx(rename = "user.last_name")]
    pub user_last_name: Option<String>,
    #[sqlx(rename = "user.avatar_path")]
    pub user_avatar_path: Option<String>,
    #[sqlx(rename = "user.is_verified")]
    pub user_is_verified: bool,
    #[sqlx(rename = "role.id")]
    pub role_id: Option<Uuid>,
    #[sqlx(rename = "role.name")]
    pub role_name: Option<String>,
    #[sqlx(rename = "role.created_at")]
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
