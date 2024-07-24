use sqlx::{Error, MySql, Pool, query, query_as};
use uuid::Uuid;
use crate::domain::role::Role;

#[derive(Clone)]
pub struct MysqlRoleRepository {
    pool: Pool<MySql>,
}

impl MysqlRoleRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }

    pub async fn add(&self, role: &Role) -> Result<(), Error> {
        query("INSERT INTO roles (id, name, created_at) VALUES (?, ?, ?)")
            .bind(&role.id)
            .bind(&role.name)
            .bind(&role.created_at)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_by_id(&self, id: Uuid) -> Option<Role> {
        query_as::<_, Role>("SELECT * FROM roles WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .ok()
    }

    pub async fn get_by_name(&self, name: &String) -> Option<Role> {
        query_as::<_, Role>("SELECT * FROM roles WHERE name = ?")
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .ok()
    }

    pub async fn get_all(&self) -> Vec<Role> {
        query_as::<_, Role>("SELECT * FROM roles")
            .fetch_all(&self.pool)
            .await
            .unwrap_or(vec![])
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), Error> {
        query("DELETE FROM roles WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn delete_by_name(&self, name: &String) -> Result<(), Error> {
        query("DELETE FROM roles WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
