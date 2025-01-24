use crate::domain::repository::RepositoryError;
use crate::domain::repository::PermissionRepository;
use crate::domain::permission::Permission;
use async_trait::async_trait;
use sqlx::{query_as, Pool, Sqlite};
use uuid::Uuid;

#[derive(Clone)]
pub struct SqlitePermissionRepository {
    pool: Pool<Sqlite>,
}

impl SqlitePermissionRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionRepository for SqlitePermissionRepository {
    async fn save(&self, permission: &Permission) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let existing_permission = sqlx::query_as::<_, Permission>(
            "SELECT * FROM permissions WHERE id = ?"
        )
        .bind(permission.id)
        .fetch_optional(&mut *tx)
        .await?;

        match existing_permission {
            Some(_) => {
                sqlx::query(
                    "UPDATE permissions SET name = ?, group_name = ?, description = ?, is_system = ?, created_at = ? WHERE id = ?"
                )
                .bind(&permission.name)
                .bind(&permission.group_name)
                .bind(&permission.description)
                .bind(&permission.is_system)
                .bind(&permission.created_at)
                .bind(&permission.id)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                sqlx::query(
                    "INSERT INTO permissions (id, name, group_name, description, is_system, created_at) VALUES (?, ?, ?, ?, ?, ?)"
                )
                .bind(&permission.id)
                .bind(&permission.name)
                .bind(&permission.group_name)
                .bind(&permission.description)
                .bind(&permission.is_system)
                .bind(&permission.created_at)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Permission, RepositoryError> {
        let permission = query_as::<_, Permission>("SELECT * FROM permissions WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;

        Ok(permission)
    }

    async fn get_by_name(&self, name: &str, group_name: &str) -> Result<Permission, RepositoryError> {
        let permission = query_as::<_, Permission>(
            "SELECT * FROM permissions WHERE name = ? AND group_name = ?"
        )
        .bind(name)
        .bind(group_name)
        .fetch_one(&self.pool)
        .await?;

        Ok(permission)
    }

    async fn get_all(&self, offset: i32, limit: i32) -> Result<Vec<Permission>, RepositoryError> {
        let permissions = query_as::<_, Permission>(
            "SELECT * FROM permissions ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    async fn get_by_group(&self, group_name: &str) -> Result<Vec<Permission>, RepositoryError> {
        let permissions = query_as::<_, Permission>(
            "SELECT * FROM permissions WHERE group_name = ? ORDER BY created_at DESC"
        )
        .bind(group_name)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let is_system = sqlx::query_scalar::<_, bool>(
            "SELECT is_system FROM permissions WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;

        match is_system {
            None => {
                tx.rollback().await?;
                Err(RepositoryError::NotFound(format!(
                    "Permission with id {} not found",
                    id
                )))
            }
            Some(is_system) => {
                if is_system {
                    tx.rollback().await?;
                    return Err(RepositoryError::Conflict(
                        "Cannot delete system permission".to_string(),
                    ));
                }

                sqlx::query("DELETE FROM permissions WHERE id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;

                tx.commit().await?;
                Ok(())
            }
        }
    }

    async fn mark_as_system(&self, id: &Uuid) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let result = sqlx::query("UPDATE permissions SET is_system = TRUE WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(RepositoryError::NotFound(format!(
                "Permission with id {} not found",
                id
            )));
        }

        tx.commit().await?;
        Ok(())
    }
}
