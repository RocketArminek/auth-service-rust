use crate::domain::repositories::SessionRepository;
use crate::domain::session::Session;
use crate::infrastructure::repository::RepositoryError;
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use uuid::Uuid;
use crate::domain::user::User;
use crate::infrastructure::dto::UserRow;
use crate::infrastructure::dto::SessionWithUserRow;

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

    async fn get_session_with_user(&self, id: &Uuid) -> Result<(Session, User), RepositoryError> {
        let row = sqlx::query_as::<_, SessionWithUserRow>(
            r#"
            SELECT 
                s.*,
                u.id as "user.id",
                u.email as "user.email",
                u.password as "user.password",
                u.created_at as "user.created_at",
                u.first_name as "user.first_name",
                u.last_name as "user.last_name",
                u.avatar_path as "user.avatar_path",
                u.is_verified as "user.is_verified"
            FROM sessions s
            INNER JOIN users u ON s.user_id = u.id
            WHERE s.id = ?
            "#,
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                RepositoryError::NotFound(format!("Session not found with id: {}", id))
            }
            _ => RepositoryError::Database(e),
        })?;

        Ok(row.into())
    }
}
