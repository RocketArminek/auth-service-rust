use crate::domain::user::{User, UserWithRoles};
use sqlx::{query, query_as, Error, MySql, Pool};
use uuid::Uuid;
use crate::domain::role::Role;

#[derive(Clone)]
pub struct MysqlUserRepository {
    pool: Pool<MySql>,
}

impl MysqlUserRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }

    pub async fn add(&self, user: &User) -> Result<(), Error> {
        query("INSERT INTO users (id, email, password, created_at) VALUES (?, ?, ?, ?)")
            .bind(&user.id)
            .bind(&user.email)
            .bind(&user.password)
            .bind(&user.created_at)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn add_role(&self, user_id: Uuid, role_id: Uuid) -> Result<(), Error> {
        query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
            .bind(&user_id)
            .bind(&role_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn add_with_role(&self, user: &User, role_id: Uuid) -> Result<(), Error> {
        let mut tx = self.pool.begin().await?;

        let user_query = query("INSERT INTO users (id, email, password, created_at) VALUES (?, ?, ?, ?)")
            .bind(&user.id)
            .bind(&user.email)
            .bind(&user.password)
            .bind(&user.created_at)
            .execute(&mut *tx)
            .await;

        let role_query = query("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)")
            .bind(&user.id)
            .bind(&role_id)
            .execute(&mut *tx)
            .await;

        match (user_query, role_query) {
            (Ok(_), Ok(_)) => tx.commit().await,
            (Err(uce), Err(_)) => {
                tx.rollback().await?;

                Err(uce)
            },
            (Ok(_), Err(rce)) => {
                tx.rollback().await?;

                Err(rce)
            },
            (Err(uce), Ok(_)) => {
                tx.rollback().await?;

                Err(uce)
            },
        }
    }

    pub async fn get_by_id(&self, id: Uuid) -> Option<UserWithRoles> {
        let user = query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .ok();

        let roles = query_as::<_, Role>("SELECT r.* FROM roles r JOIN user_roles ur ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id WHERE u.id = ?")
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .unwrap_or(vec![]);

        user.map(|user| UserWithRoles::from_user_and_roles(user, roles))
    }

    pub async fn get_by_email(&self, email: &String) -> Option<UserWithRoles> {
        let user = query_as::<_, User>("SELECT * FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .ok();

        let roles = query_as::<_, Role>("SELECT r.* FROM roles r JOIN user_roles ur ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id WHERE u.email = ?")
            .bind(email)
            .fetch_all(&self.pool)
            .await
            .unwrap_or(vec![]);

        user.map(|user| UserWithRoles::from_user_and_roles(user, roles))
    }

    pub async fn delete_by_email(&self, email: &String) -> Result<(), Error> {
        query("DELETE FROM users WHERE email = ?")
            .bind(email)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
