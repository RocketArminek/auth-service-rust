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

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        User {
            id: row.id,
            email: row.email,
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
