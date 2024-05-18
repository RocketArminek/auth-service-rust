use chrono::{DateTime, Timelike, Utc};
use sqlx::FromRow;
use uuid::{NoContext, Timestamp, Uuid};
use crate::domain::error::RoleError;

#[derive(FromRow, Debug)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

impl Role {
    pub fn new(id: Uuid, name: String, created_at: DateTime<Utc>) -> Result<Self, RoleError> {
        if name.is_empty() {
            Err(RoleError::Empty)
        } else {
            Ok(Role { id, name, created_at })
        }
    }

    pub fn now(name: String) -> Result<Self, RoleError> {
        let now = Utc::now();
        let timestamp = Timestamp::from_unix(NoContext, now.timestamp() as u64, now.nanosecond());

        Role::new(Uuid::new_v7(timestamp), name, now)
    }
}
