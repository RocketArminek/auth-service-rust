use crate::domain::repositories::SessionRepository;
use crate::domain::session::Session;
use crate::infrastructure::repository::RepositoryError;
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteSessionRepository {
    pool: Pool<Sqlite>,
}

impl SqliteSessionRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for SqliteSessionRepository {
    async fn save(&self, session: &Session) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let existing_session = sqlx::query("SELECT id FROM sessions WHERE id = ?")
            .bind(&session.id)
            .fetch_optional(&mut *tx)
            .await?;

        match existing_session {
            Some(_) => {
                sqlx::query(
                    r#"
                    UPDATE sessions 
                    SET user_id = ?, created_at = ?, expires_at = ?
                    WHERE id = ?
                    "#,
                )
                .bind(&session.user_id)
                .bind(&session.created_at)
                .bind(&session.expires_at)
                .bind(&session.id)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                sqlx::query(
                    r#"
                    INSERT INTO sessions (id, user_id, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    "#,
                )
                .bind(&session.id)
                .bind(&session.user_id)
                .bind(&session.created_at)
                .bind(&session.expires_at)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Session, RepositoryError> {
        let session = sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;

        Ok(session)
    }

    async fn get_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Session>, RepositoryError> {
        let sessions = sqlx::query_as::<_, Session>(
            "SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(sessions)
    }

    async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_all_by_user_id(&self, user_id: &Uuid) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
} 