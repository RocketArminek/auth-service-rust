use crate::domain::permission::Permission;
use crate::domain::user::User;
use crate::infrastructure::dto::{UserWithPermissionsRow, UserWithRoleRow};
use crate::infrastructure::repository::RepositoryError;
use sqlx::{Error, Pool, Sqlite, query};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteUserRepository {
    pool: Pool<Sqlite>,
}

impl SqliteUserRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    pub async fn save(&self, user: &User) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let existing_user = sqlx::query("SELECT id FROM users WHERE id = ?")
            .bind(user.id)
            .fetch_optional(&mut *tx)
            .await?;

        match existing_user {
            Some(_) => {
                sqlx::query(
                    r#"
                    UPDATE users
                    SET email = ?,
                        password = ?,
                        created_at = ?,
                        first_name = ?,
                        last_name = ?,
                        avatar_path = ?,
                        is_verified = ?
                    WHERE id = ?
                    "#,
                )
                .bind(&user.email)
                .bind(&user.password)
                .bind(user.created_at)
                .bind(&user.first_name)
                .bind(&user.last_name)
                .bind(&user.avatar_path)
                .bind(user.is_verified)
                .bind(user.id)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                sqlx::query(
                    r#"
                    INSERT INTO users (
                        id, email, password, created_at,
                        first_name, last_name, avatar_path, is_verified
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(user.id)
                .bind(&user.email)
                .bind(&user.password)
                .bind(user.created_at)
                .bind(&user.first_name)
                .bind(&user.last_name)
                .bind(&user.avatar_path)
                .bind(user.is_verified)
                .execute(&mut *tx)
                .await?;
            }
        }

        sqlx::query("DELETE FROM user_roles WHERE user_id = ?")
            .bind(user.id)
            .execute(&mut *tx)
            .await?;

        if !user.roles.is_empty() {
            let placeholders = "?,".repeat(user.roles.len());
            let query = format!(
                "SELECT COUNT(id) as count FROM roles WHERE id IN ({})",
                placeholders.trim_end_matches(',')
            );

            let mut q = sqlx::query_as::<_, (i64,)>(&query);
            for role in &user.roles {
                q = q.bind(role.id);
            }

            let found_roles = q.fetch_one(&mut *tx).await?;

            if (found_roles.0 as usize) != user.roles.len() {
                tx.rollback().await?;
                return Err(RepositoryError::NotFound(
                    "One or more roles not found".to_string(),
                ));
            }

            for role in &user.roles {
                sqlx::query(
                    r#"
                INSERT INTO user_roles (user_id, role_id)
                VALUES (?, ?)
                "#,
                )
                .bind(user.id)
                .bind(role.id)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;

        Ok(())
    }

    pub async fn get_by_id(&self, id: &Uuid) -> Result<User, RepositoryError> {
        let rows = sqlx::query_as::<_, UserWithRoleRow>(
            r#"
            SELECT
                u.id,
                u.email,
                u.password,
                u.created_at,
                u.first_name,
                u.last_name,
                u.avatar_path,
                u.is_verified,
                r.id as role_id,
                r.name as role_name,
                r.created_at as role_created_at
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE u.id = ?
            "#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| match e {
            Error::RowNotFound => {
                RepositoryError::NotFound(format!("User not found with id: {}", id))
            }
            _ => RepositoryError::Database(e),
        })?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!(
                "User not found with id: {}",
                id
            )));
        }

        let mut user = User::from(&rows[0]);
        user.roles = rows.iter().filter_map(|row| row.extract_role()).collect();

        Ok(user)
    }

    pub async fn get_by_email(&self, email: &str) -> Result<User, RepositoryError> {
        let rows = sqlx::query_as::<_, UserWithRoleRow>(
            r#"
            SELECT
                u.id,
                u.email,
                u.password,
                u.created_at,
                u.first_name,
                u.last_name,
                u.avatar_path,
                u.is_verified,
                r.id as role_id,
                r.name as role_name,
                r.created_at as role_created_at
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            WHERE u.email = ?
            "#,
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| match e {
            Error::RowNotFound => {
                RepositoryError::NotFound(format!("User not found with email: {}", email))
            }
            _ => RepositoryError::Database(e),
        })?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!(
                "User not found with email: {}",
                email
            )));
        }

        let mut user = User::from(&rows[0]);
        user.roles = rows.iter().filter_map(|row| row.extract_role()).collect();

        Ok(user)
    }

    pub async fn delete_by_email(&self, email: &str) -> Result<(), RepositoryError> {
        query("DELETE FROM users WHERE email = ?")
            .bind(email)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn find_all(
        &self,
        page: i32,
        limit: i32,
    ) -> Result<(Vec<User>, i32), RepositoryError> {
        let offset = (page - 1) * limit;

        let rows = sqlx::query_as::<_, UserWithRoleRow>(
            r#"
            SELECT
                u.id,
                u.email,
                u.password,
                u.created_at,
                u.first_name,
                u.last_name,
                u.avatar_path,
                u.is_verified,
                r.id as role_id,
                r.name as role_name,
                r.created_at as role_created_at
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            ORDER BY u.created_at DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let total: (i32,) = sqlx::query_as("SELECT COUNT(DISTINCT id) FROM users")
            .fetch_one(&self.pool)
            .await?;

        let users = self.group_user_rows(rows);

        Ok((users, total.0))
    }

    pub async fn get_by_id_with_permissions(
        &self,
        id: &Uuid,
    ) -> Result<(User, Vec<Permission>), RepositoryError> {
        let rows = sqlx::query_as::<_, UserWithPermissionsRow>(
            r#"
            SELECT
                u.id,
                u.email,
                u.password,
                u.created_at,
                u.first_name,
                u.last_name,
                u.avatar_path,
                u.is_verified,
                r.id as role_id,
                r.name as role_name,
                r.created_at as role_created_at,
                p.id as permission_id,
                p.name as permission_name,
                p.group_name as permission_group_name,
                p.description as permission_description,
                p.is_system as permission_is_system,
                p.created_at as permission_created_at
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id
            WHERE u.id = ?
            "#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| match e {
            Error::RowNotFound => {
                RepositoryError::NotFound(format!("User not found with id: {}", id))
            }
            _ => RepositoryError::Database(e),
        })?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!(
                "User not found with id: {}",
                id
            )));
        }

        let mut user = User::from(&rows[0]);
        user.roles = rows.iter().filter_map(|row| row.extract_role()).collect();

        let permissions: Vec<Permission> = rows
            .iter()
            .filter_map(|row| row.extract_permission())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        Ok((user, permissions))
    }

    pub async fn get_by_email_with_permissions(
        &self,
        email: &str,
    ) -> Result<(User, Vec<Permission>), RepositoryError> {
        let rows = sqlx::query_as::<_, UserWithPermissionsRow>(
            r#"
            SELECT
                u.id,
                u.email,
                u.password,
                u.created_at,
                u.first_name,
                u.last_name,
                u.avatar_path,
                u.is_verified,
                r.id as role_id,
                r.name as role_name,
                r.created_at as role_created_at,
                p.id as permission_id,
                p.name as permission_name,
                p.group_name as permission_group_name,
                p.description as permission_description,
                p.is_system as permission_is_system,
                p.created_at as permission_created_at
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id
            WHERE u.email = ?
            "#,
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| match e {
            Error::RowNotFound => {
                RepositoryError::NotFound(format!("User not found with email: {}", email))
            }
            _ => RepositoryError::Database(e),
        })?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!(
                "User not found with email: {}",
                email
            )));
        }

        let mut user = User::from(&rows[0]);
        user.roles = rows.iter().filter_map(|row| row.extract_role()).collect();

        let permissions = rows
            .iter()
            .filter_map(|row| row.extract_permission())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        Ok((user, permissions))
    }

    fn group_user_rows(&self, rows: Vec<UserWithRoleRow>) -> Vec<User> {
        let mut users_map: HashMap<Uuid, User> = HashMap::new();

        for row in rows {
            let user = users_map.entry(row.id).or_insert_with(|| User::from(&row));

            if let Some(role) = row.extract_role() {
                if !user.roles.iter().any(|r| r.id == role.id) {
                    user.roles.push(role);
                }
            }
        }

        users_map.into_values().collect()
    }
}
