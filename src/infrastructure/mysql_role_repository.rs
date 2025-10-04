use crate::domain::permission::Permission;
use crate::domain::role::Role;
use crate::infrastructure::dto::RoleWithPermissionsRow;
use crate::infrastructure::repository::RepositoryError;
use sqlx::{MySql, Pool, query_as};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone)]
pub struct MysqlRoleRepository {
    pool: Pool<MySql>,
}

impl MysqlRoleRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }

    pub async fn save(&self, role: &Role) -> Result<(), RepositoryError> {
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

    pub async fn get_by_id(&self, id: &Uuid) -> Result<Role, RepositoryError> {
        let role = query_as::<_, Role>("SELECT * FROM roles WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;

        Ok(role)
    }

    pub async fn get_by_name(&self, name: &str) -> Result<Role, RepositoryError> {
        let role = query_as::<_, Role>("SELECT * FROM roles WHERE name = ?")
            .bind(name)
            .fetch_one(&self.pool)
            .await?;

        Ok(role)
    }

    pub async fn delete(&self, id: &Uuid) -> Result<(), RepositoryError> {
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

    pub async fn delete_by_name(&self, name: &str) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let is_system = sqlx::query_scalar::<_, bool>("SELECT is_system FROM roles WHERE name = ?")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;

        match is_system {
            None => {
                tx.rollback().await?;
                Err(RepositoryError::NotFound(format!(
                    "Role with name {} not found",
                    name
                )))
            }
            Some(is_system) => {
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
        }
    }

    pub async fn get_all(&self, page: i32, limit: i32) -> Result<Vec<Role>, RepositoryError> {
        let offset = (page - 1) * limit;

        let roles =
            query_as::<_, Role>("SELECT * FROM roles ORDER BY created_at DESC LIMIT ? OFFSET ?")
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?;

        Ok(roles)
    }

    pub async fn mark_as_system(&self, id: &Uuid) -> Result<(), RepositoryError> {
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

    pub async fn add_permission(
        &self,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let is_system = sqlx::query_scalar::<_, bool>("SELECT is_system FROM roles WHERE id = ?")
            .bind(role_id)
            .fetch_optional(&mut *tx)
            .await?;

        match is_system {
            None => {
                return Err(RepositoryError::NotFound(format!(
                    "Role with id {} not found",
                    role_id
                )));
            }
            Some(is_system) => {
                if is_system {
                    return Err(RepositoryError::ValidationError(
                        "Cannot modify permissions for system role".to_string(),
                    ));
                }
            }
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

        if exists {
            return Ok(());
        }

        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)")
            .bind(role_id)
            .bind(permission_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_permission(
        &self,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let is_system = sqlx::query_scalar::<_, bool>("SELECT is_system FROM roles WHERE id = ?")
            .bind(role_id)
            .fetch_optional(&mut *tx)
            .await?;

        match is_system {
            None => {
                return Err(RepositoryError::NotFound(format!(
                    "Role with id {} not found",
                    role_id
                )));
            }
            Some(is_system) => {
                if is_system {
                    return Err(RepositoryError::ValidationError(
                        "Cannot modify permissions for system role".to_string(),
                    ));
                }
            }
        }

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

    pub async fn get_permissions(
        &self,
        role_id: &Uuid,
    ) -> Result<Vec<Permission>, RepositoryError> {
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

    pub async fn get_permissions_for_roles(
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

    pub async fn get_by_id_with_permissions(
        &self,
        role_id: &Uuid,
    ) -> Result<(Role, Vec<Permission>), RepositoryError> {
        let rows = sqlx::query_as::<_, RoleWithPermissionsRow>(
            r#"
            SELECT
                r.id, r.name, r.created_at, r.is_system,
                p.id as permission_id,
                p.name as permission_name,
                p.group_name as permission_group_name,
                p.description as permission_description,
                p.is_system as permission_is_system,
                p.created_at as permission_created_at
            FROM roles r
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id
            WHERE r.id = ?
            "#,
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!(
                "Role with id {} not found",
                role_id
            )));
        }

        let first_row = &rows[0];
        let role = Role {
            id: first_row.id,
            name: first_row.name.clone(),
            created_at: first_row.created_at,
        };

        let permissions: Vec<Permission> = rows
            .into_iter()
            .filter_map(|row| {
                let (_, permission) = row.into_role_and_permission();
                permission
            })
            .collect();

        Ok((role, permissions))
    }

    pub async fn get_by_name_with_permissions(
        &self,
        name: &str,
    ) -> Result<(Role, Vec<Permission>), RepositoryError> {
        let rows = sqlx::query_as::<_, RoleWithPermissionsRow>(
            r#"
            SELECT
                r.id, r.name, r.created_at, r.is_system,
                p.id as permission_id,
                p.name as permission_name,
                p.group_name as permission_group_name,
                p.description as permission_description,
                p.is_system as permission_is_system,
                p.created_at as permission_created_at
            FROM roles r
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id
            WHERE r.name = ?
            "#,
        )
        .bind(name)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!(
                "Role with name {} not found",
                name
            )));
        }

        let first_row = &rows[0];
        let role = Role {
            id: first_row.id,
            name: first_row.name.clone(),
            created_at: first_row.created_at,
        };

        let permissions: Vec<Permission> = rows
            .into_iter()
            .filter_map(|row| {
                let (_, permission) = row.into_role_and_permission();
                permission
            })
            .collect();

        Ok((role, permissions))
    }

    pub async fn get_all_with_permissions(
        &self,
        page: i32,
        limit: i32,
    ) -> Result<Vec<(Role, Vec<Permission>)>, RepositoryError> {
        let offset = (page - 1) * limit;

        let rows = sqlx::query_as::<_, RoleWithPermissionsRow>(
            r#"
            SELECT
                r.id, r.name, r.created_at, r.is_system,
                p.id as permission_id,
                p.name as permission_name,
                p.group_name as permission_group_name,
                p.description as permission_description,
                p.is_system as permission_is_system,
                p.created_at as permission_created_at
            FROM roles r
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id
            ORDER BY r.name
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut role_map: HashMap<Uuid, (Role, Vec<Permission>)> = HashMap::new();

        for row in rows {
            let role_entry = role_map.entry(row.id).or_insert_with(|| {
                let role = Role {
                    id: row.id,
                    name: row.name.clone(),
                    created_at: row.created_at,
                };
                (role, Vec::new())
            });

            let (_, permission) = row.into_role_and_permission();

            if permission.is_some() {
                role_entry.1.push(permission.unwrap());
            }
        }

        Ok(role_map.into_values().collect())
    }
}
