use crate::domain::repository::RoleRepository;
use crate::domain::role::Role;
use crate::domain::repository::RepositoryError;
use async_trait::async_trait;
use sqlx::{query_as, MySql, Pool};
use uuid::Uuid;

#[derive(Clone)]
pub struct MysqlRoleRepository {
    pool: Pool<MySql>,
}

impl MysqlRoleRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for MysqlRoleRepository {
    async fn save(&self, role: &Role) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let existing_role = sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = ?")
            .bind(role.id)
            .fetch_optional(&mut *tx)
            .await?;

        match existing_role {
            Some(_) => {
                sqlx::query("UPDATE roles SET name = ?, created_at = ? WHERE id = ?")
                    .bind(&role.name)
                    .bind(&role.created_at)
                    .bind(&role.id)
                    .execute(&mut *tx)
                    .await?;
            }
            None => {
                sqlx::query("INSERT INTO roles (id, name, created_at) VALUES (?, ?, ?)")
                    .bind(&role.id)
                    .bind(&role.name)
                    .bind(&role.created_at)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_by_id(&self, id: &Uuid) -> Result<Role, RepositoryError> {
        let role = query_as::<_, Role>("SELECT * FROM roles WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;

        Ok(role)
    }

    async fn get_by_name(&self, name: &str) -> Result<Role, RepositoryError> {
        let role = query_as::<_, Role>("SELECT * FROM roles WHERE name = ?")
            .bind(name)
            .fetch_one(&self.pool)
            .await?;

        Ok(role)
    }

    async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let is_system = sqlx::query_scalar::<_, bool>("SELECT is_system FROM roles WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(false);

        if is_system {
            tx.rollback().await?;
            return Err(RepositoryError::Conflict(
                "Cannot delete system role".to_string(),
            ));
        }

        sqlx::query("DELETE FROM roles WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn delete_by_name(&self, name: &str) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let is_system = sqlx::query_scalar::<_, bool>("SELECT is_system FROM roles WHERE name = ?")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(false);

        if is_system {
            tx.rollback().await?;
            return Err(RepositoryError::Conflict(
                "Cannot delete system role".to_string(),
            ));
        }

        sqlx::query("DELETE FROM roles WHERE name = ?")
            .bind(name)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn get_all(&self, offset: i32, limit: i32) -> Result<Vec<Role>, RepositoryError> {
        let roles =
            query_as::<_, Role>("SELECT * FROM roles ORDER BY created_at DESC LIMIT ? OFFSET ?")
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?;

        Ok(roles)
    }

    async fn mark_as_system(&self, id: &Uuid) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let result = sqlx::query("UPDATE roles SET is_system = TRUE WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(RepositoryError::NotFound(format!(
                "Role with id {} not found",
                id
            )));
        }

        tx.commit().await?;
        Ok(())
    }
}
