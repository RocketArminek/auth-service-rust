use crate::domain::error::PermissionError;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct Permission {
    pub id: Uuid,
    pub name: String,
    pub group_name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
}

impl Permission {
    pub fn new(
        id: Uuid,
        name: String,
        group_name: String,
        description: Option<String>,
        is_system: bool,
        created_at: DateTime<Utc>,
    ) -> Result<Self, PermissionError> {
        if name.trim().is_empty() {
            return Err(PermissionError::EmptyName);
        }

        if group_name.trim().is_empty() {
            return Err(PermissionError::EmptyGroupName);
        }

        Ok(Self {
            id,
            name,
            group_name,
            description,
            is_system,
            created_at,
        })
    }

    pub fn now(
        name: String,
        group_name: String,
        description: Option<String>,
    ) -> Result<Self, PermissionError> {
        Self::new(
            Uuid::new_v4(),
            name,
            group_name,
            description,
            false,
            Utc::now(),
        )
    }
}
