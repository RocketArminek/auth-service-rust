use crate::domain::permission::Permission;
use crate::domain::repository::RepositoryError;
use crate::domain::repository::RoleRepository;
use crate::domain::role::Role;
use async_trait::async_trait;
use sqlx::{query_as, Pool, Sqlite};
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteRoleRepository {
    pool: Pool<Sqlite>,
}

impl SqliteRoleRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for SqliteRoleRepository {
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
                    .bind(role.created_at)
                    .bind(role.id)
                    .execute(&mut *tx)
                    .await?;
            }
            None => {
                sqlx::query("INSERT INTO roles (id, name, created_at) VALUES (?, ?, ?)")
                    .bind(role.id)
                    .bind(&role.name)
                    .bind(role.created_at)
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

    async fn add_permission(
        &self,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let role = sqlx::query_scalar::<_, bool>("SELECT is_system FROM roles WHERE id = ?")
            .bind(role_id)
            .fetch_optional(&mut *tx)
            .await?;

        if role.is_none() {
            return Err(RepositoryError::NotFound("Role not found".to_string()));
        }

        let permission_exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM permissions WHERE id = ?)")
                .bind(permission_id)
                .fetch_one(&mut *tx)
                .await?;

        if !permission_exists {
            return Err(RepositoryError::NotFound(
                "Permission not found".to_string(),
            ));
        }

        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM role_permissions WHERE role_id = ? AND permission_id = ?)",
        )
        .bind(role_id)
        .bind(permission_id)
        .fetch_one(&mut *tx)
        .await?;

        if !exists {
            sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)")
                .bind(role_id)
                .bind(permission_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn remove_permission(
        &self,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let result =
            sqlx::query("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?")
                .bind(role_id)
                .bind(permission_id)
                .execute(&mut *tx)
                .await?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound(
                "Role-Permission relationship not found".to_string(),
            ));
        }

        tx.commit().await?;
        Ok(())
    }

    async fn get_permissions(&self, role_id: &Uuid) -> Result<Vec<Permission>, RepositoryError> {
        let permissions = sqlx::query_as::<_, Permission>(
            "SELECT p.* FROM permissions p
             INNER JOIN role_permissions rp ON p.id = rp.permission_id
             WHERE rp.role_id = ?",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(permissions)
    }

    async fn get_permissions_for_roles(
        &self,
        role_ids: &[Uuid],
    ) -> Result<Vec<Permission>, RepositoryError> {
        if role_ids.is_empty() {
            return Ok(Vec::new());
        }

        let query = format!(
            "SELECT DISTINCT p.* FROM permissions p 
             INNER JOIN role_permissions rp ON p.id = rp.permission_id 
             WHERE rp.role_id IN ({})",
            role_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",")
        );

        let mut q = sqlx::query_as::<_, Permission>(&query);
        for role_id in role_ids {
            q = q.bind(role_id);
        }

        let permissions = q.fetch_all(&self.pool).await?;
        Ok(permissions)
    }
}
