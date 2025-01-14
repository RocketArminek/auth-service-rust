use chrono::{DateTime, Timelike, Utc};
use uuid::{NoContext, Timestamp, Uuid};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Session {
    pub fn new(
        id: Uuid,
        user_id: Uuid,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            user_id,
            created_at,
            expires_at,
        }
    }

    pub fn now(user_id: Uuid, expires_at: DateTime<Utc>) -> Self {
        let now = Utc::now();
        let timestamp = Timestamp::from_unix(NoContext, now.timestamp() as u64, now.nanosecond());

        Self::new(Uuid::new_v7(timestamp), user_id, now, expires_at)
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}
