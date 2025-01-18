use crate::domain::repositories::SessionRepository;
use crate::domain::role::Role;
use crate::domain::session::Session;
use crate::domain::user::User;
use crate::infrastructure::dto::SessionWithUserRow;
use crate::infrastructure::repository::RepositoryError;
use async_trait::async_trait;
use chrono::Utc;
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

    async fn get_session_with_user(&self, id: &Uuid) -> Result<(Session, User), RepositoryError> {
        let rows = sqlx::query_as::<_, SessionWithUserRow>(
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
                u.is_verified as "user.is_verified",
                r.id as "role.id",
                r.name as "role.name",
                r.created_at as "role.created_at"
            FROM sessions s
            INNER JOIN users u ON s.user_id = u.id
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE s.id = ?
            "#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                RepositoryError::NotFound(format!("Session not found with id: {}", id))
            }
            _ => RepositoryError::Database(e),
        })?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!(
                "Session not found with id: {}",
                id
            )));
        }

        let first_row = &rows[0];
        let session = Session {
            id: first_row.id,
            user_id: first_row.user_id,
            created_at: first_row.created_at,
            expires_at: first_row.expires_at,
        };

        let mut user = User {
            id: first_row.user_id_alias,
            email: first_row.user_email.clone(),
            password: first_row.user_password.clone(),
            not_hashed_password: String::new(),
            created_at: first_row.user_created_at,
            first_name: first_row.user_first_name.clone(),
            last_name: first_row.user_last_name.clone(),
            avatar_path: first_row.user_avatar_path.clone(),
            is_verified: first_row.user_is_verified,
            roles: Vec::new(),
        };

        let roles = rows
            .iter()
            .filter_map(|row| {
                row.role_id.map(|role_id| Role {
                    id: role_id,
                    name: row.role_name.clone().unwrap_or_default(),
                    created_at: row.role_created_at.unwrap_or(row.created_at),
                })
            })
            .collect();

        user.roles = roles;

        Ok((session, user))
    }

    async fn get_all(&self, page: i32, limit: i32) -> Result<(Vec<Session>, i32), RepositoryError> {
        let offset = (page - 1) * limit;

        let total = sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM sessions")
            .fetch_one(&self.pool)
            .await?;

        let sessions = sqlx::query_as::<_, Session>(
            "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((sessions, total))
    }

    async fn delete_expired(&self) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now();

        sqlx::query(
            r#"
            DELETE FROM sessions 
            WHERE expires_at < ?
            "#,
        )
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }
}
