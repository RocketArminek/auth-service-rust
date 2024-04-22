use sqlx::{Error, MySql, Pool, query, query_as};
use uuid::Uuid;
use crate::domain::user::User;

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

    pub async fn get_by_id(&self, id: Uuid) -> Option<User> {
        query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .ok()
    }

    pub async fn get_by_email(&self, email: &String) -> Option<User> {
        query_as::<_, User>("SELECT * FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .ok()
    }
}
