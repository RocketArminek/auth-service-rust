use crate::domain::repository::RepositoryError;
use crate::domain::repository::UserRepository;
use crate::domain::role::Role;
use crate::domain::user::User;
use crate::infrastructure::dto::{UserWithPermissionsRow, UserWithRoleRow};
use async_trait::async_trait;
use sqlx::{query, Error, Pool, Sqlite};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use crate::domain::permission::Permission;

#[derive(Clone)]
pub struct SqliteUserRepository {
    pool: Pool<Sqlite>,
}

impl SqliteUserRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    fn group_user_rows(&self, rows: Vec<UserWithRoleRow>) -> Vec<User> {
        let mut users_map: HashMap<Uuid, (User, Vec<Role>)> = HashMap::new();

        for row in rows {
            let user_entry = users_map.entry(row.id).or_insert_with(|| {
                let user = User {
                    id: row.id,
                    email: row.email.clone(),
                    not_hashed_password: "".to_string(),
                    password: row.password.clone(),
                    first_name: row.first_name.clone(),
                    last_name: row.last_name.clone(),
                    created_at: row.created_at,
                    avatar_path: row.avatar_path.clone(),
                    is_verified: row.is_verified,
                    roles: Vec::new(),
                };
                (user, Vec::new())
            });

            if let Some(role_id) = row.role_id {
                if let Some(role_name) = &row.role_name {
                    if !user_entry.1.iter().any(|r| r.id == role_id) {
                        user_entry.1.push(Role {
                            id: role_id,
                            name: role_name.clone(),
                            created_at: row.role_created_at.unwrap_or(row.created_at),
                        });
                    }
                }
            }
        }

        users_map
            .into_iter()
            .map(|(_, (mut user, roles))| {
                user.roles = roles;
                user
            })
            .collect()
    }
}

#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn save(&self, user: &User) -> Result<(), RepositoryError> {
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

    async fn get_by_id(&self, id: &Uuid) -> Result<User, RepositoryError> {
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

        let first_row = &rows[0];
        let mut user = User {
            id: first_row.id,
            email: first_row.email.clone(),
            not_hashed_password: "".to_string(),
            password: first_row.password.clone(),
            first_name: first_row.first_name.clone(),
            last_name: first_row.last_name.clone(),
            created_at: first_row.created_at,
            avatar_path: first_row.avatar_path.clone(),
            is_verified: first_row.is_verified,
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

        Ok(user)
    }

    async fn get_by_email(&self, email: &str) -> Result<User, RepositoryError> {
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

        let first_row = &rows[0];
        let mut user = User {
            id: first_row.id,
            email: first_row.email.clone(),
            not_hashed_password: "".to_string(),
            password: first_row.password.clone(),
            first_name: first_row.first_name.clone(),
            last_name: first_row.last_name.clone(),
            created_at: first_row.created_at,
            avatar_path: first_row.avatar_path.clone(),
            is_verified: first_row.is_verified,
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

        Ok(user)
    }

    async fn delete_by_email(&self, email: &str) -> Result<(), RepositoryError> {
        query("DELETE FROM users WHERE email = ?")
            .bind(email)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn find_all(&self, page: i32, limit: i32) -> Result<(Vec<User>, i32), RepositoryError> {
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

    async fn get_by_id_with_permissions(&self, id: &Uuid) -> Result<(User, Vec<Permission>), RepositoryError> {
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

        let first_row = &rows[0];
        let mut user = User {
            id: first_row.id,
            email: first_row.email.clone(),
            not_hashed_password: "".to_string(),
            password: first_row.password.clone(),
            first_name: first_row.first_name.clone(),
            last_name: first_row.last_name.clone(),
            created_at: first_row.created_at,
            avatar_path: first_row.avatar_path.clone(),
            is_verified: first_row.is_verified,
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

        let permissions: Vec<Permission> = rows
            .iter()
            .filter_map(|row| {
                row.permission_id.map(|permission_id| Permission {
                    id: permission_id,
                    name: row.permission_name.clone().unwrap_or_default(),
                    group_name: row.permission_group_name.clone().unwrap_or_default(),
                    description: row.permission_description.clone(),
                    created_at: row.permission_created_at.unwrap_or(row.created_at),
                    is_system: row.permission_is_system.unwrap_or(false),
                })
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        Ok((user, permissions))
    }

    async fn get_by_email_with_permissions(&self, email: &str) -> Result<(User, Vec<Permission>), RepositoryError> {
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

        let first_row = &rows[0];
        let mut user = User {
            id: first_row.id,
            email: first_row.email.clone(),
            not_hashed_password: "".to_string(),
            password: first_row.password.clone(),
            first_name: first_row.first_name.clone(),
            last_name: first_row.last_name.clone(),
            created_at: first_row.created_at,
            avatar_path: first_row.avatar_path.clone(),
            is_verified: first_row.is_verified,
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

        let permissions = rows
            .iter()
            .filter_map(|row| {
                row.permission_id.map(|permission_id| Permission {
                    id: permission_id,
                    name: row.permission_name.clone().unwrap_or_default(),
                    group_name: row.permission_group_name.clone().unwrap_or_default(),
                    description: row.permission_description.clone(),
                    created_at: row.permission_created_at.unwrap_or(row.created_at),
                    is_system: row.permission_is_system.unwrap_or(false),
                })
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        Ok((user, permissions))
    }
}
