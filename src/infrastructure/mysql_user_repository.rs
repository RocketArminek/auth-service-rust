use crate::domain::role::Role;
use crate::domain::user::User;
use crate::infrastructure::dto::{UserWithRoleRow};
use sqlx::{query, Error, MySql, Pool};
use uuid::Uuid;
use crate::infrastructure::repository::RepositoryError;

#[derive(Clone)]
pub struct MysqlUserRepository {
    pool: Pool<MySql>,
}

impl MysqlUserRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }

    pub async fn add(&self, user: &User) -> Result<(), RepositoryError> {
        query("INSERT INTO users (id, email, password, created_at, first_name, last_name, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(&user.id)
            .bind(&user.email)
            .bind(&user.password)
            .bind(&user.created_at)
            .bind(&user.first_name)
            .bind(&user.last_name)
            .bind(&user.is_verified)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn update(&self, user: &User) -> Result<(), RepositoryError> {
        query("UPDATE users SET email = ?, password = ?, created_at = ?, first_name = ?, last_name = ?, avatar_path = ?, is_verified = ? WHERE id = ?")
            .bind(&user.email)
            .bind(&user.password)
            .bind(&user.created_at)
            .bind(&user.first_name)
            .bind(&user.last_name)
            .bind(&user.avatar_path)
            .bind(&user.is_verified)
            .bind(&user.id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn add_role(&self, user_id: Uuid, role_id: Uuid) -> Result<(), RepositoryError> {
        query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
            .bind(&user_id)
            .bind(&role_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn add_with_role(&self, user: &User, role_id: Uuid) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;

        let user_query =
            query("INSERT INTO users (id, email, password, created_at, is_verified) VALUES (?, ?, ?, ?, ?)")
                .bind(&user.id)
                .bind(&user.email)
                .bind(&user.password)
                .bind(&user.created_at)
                .bind(&user.is_verified)
                .execute(&mut *tx)
                .await
                .map_err(
                    |e| match e {
                        Error::RowNotFound => {
                            RepositoryError::NotFound(format!("User Not found: {}", user.id))
                        }
                        _ => RepositoryError::Database(e)
                    }
                );

        let role_query = query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
            .bind(&user.id)
            .bind(&role_id)
            .execute(&mut *tx)
            .await
            .map_err(
                |e| match e {
                    Error::RowNotFound => {
                        RepositoryError::NotFound(format!("Role Not found: {}", role_id))
                    }
                    _ => RepositoryError::Database(e)
                }
            );

        match (user_query, role_query) {
            (Ok(_), Ok(_)) => {
                tx.commit().await.map_err(
                    |e| match e {
                        Error::RowNotFound => {
                            RepositoryError::NotFound("Not found".to_string())
                        }
                        _ => RepositoryError::Database(e)
                    }
                )
            },
            (Err(uce), Err(_)) => {
                tx.rollback().await?;

                Err(uce)
            }
            (Ok(_), Err(rce)) => {
                tx.rollback().await?;

                Err(rce)
            }
            (Err(uce), Ok(_)) => {
                tx.rollback().await?;

                Err(uce)
            }
        }
    }

    pub async fn get_by_id(&self, id: Uuid) -> Result<User, RepositoryError> {
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
            "#
        )
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| match e {
                Error::RowNotFound => {
                    RepositoryError::NotFound(format!("User not found with id: {}", id))
                }
                _ => RepositoryError::Database(e)
            })?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!("User not found with id: {}", id)));
        }

        let first_row = &rows[0];
        let mut user = User {
            id: first_row.id,
            email: first_row.email.clone(),
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

    pub async fn get_by_email(&self, email: &String) -> Result<User, RepositoryError> {
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
            "#
        )
            .bind(email)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| match e {
                Error::RowNotFound => {
                    RepositoryError::NotFound(format!("User not found with email: {}", email))
                }
                _ => RepositoryError::Database(e)
            })?;

        if rows.is_empty() {
            return Err(RepositoryError::NotFound(format!("User not found with email: {}", email)));
        }

        let first_row = &rows[0];
        let mut user = User {
            id: first_row.id,
            email: first_row.email.clone(),
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

    pub async fn delete_by_email(&self, email: &String) -> Result<(), Error> {
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
            "#
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

    fn group_user_rows(&self, rows: Vec<UserWithRoleRow>) -> Vec<User> {
        let mut users_map: std::collections::HashMap<Uuid, (User, Vec<Role>)> = std::collections::HashMap::new();

        for row in rows {
            let user_entry = users_map.entry(row.id).or_insert_with(|| {
                let user = User {
                    id: row.id,
                    email: row.email.clone(),
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
                user_entry.1.push(Role {
                    id: role_id,
                    name: row.role_name.unwrap_or_default(),
                    created_at: row.role_created_at.unwrap_or(row.created_at),
                });
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
