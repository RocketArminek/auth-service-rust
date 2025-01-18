use crate::domain::repositories::RoleRepository;
use crate::domain::role::Role;
use crate::infrastructure::repository::RepositoryError;
use async_trait::async_trait;
use sqlx::{query, query_as, MySql, Pool};
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
        query("DELETE FROM roles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_by_name(&self, name: &str) -> Result<(), RepositoryError> {
        query("DELETE FROM roles WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await?;

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
}
