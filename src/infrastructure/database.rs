use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Error, MySql, Pool};
use std::env;

pub async fn create_mysql_pool() -> Result<Pool<MySql>, Error> {
    let database_url = env::var("DATABASE_URL");
    if database_url.is_err() {
        let user = env::var("DATABASE_USER").expect("DATABASE_USER is not set in .env file");
        let password =
            env::var("DATABASE_PASSWORD").expect("DATABASE_PASSWORD is not set in .env file");
        let host = env::var("DATABASE_HOST").expect("DATABASE_HOST is not set in .env file");
        let database_name =
            env::var("DATABASE_NAME").expect("DATABASE_NAME is not set in .env file");
        let database_port =
            env::var("DATABASE_PORT").expect("DATABASE_PORT is not set in .env file");

        let database_url = format!(
            "mysql://{}:{}@{}:{}/{}",
            user, password, host, database_port, database_name
        );

        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;

        Ok(pool)
    } else {
        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect(&database_url.unwrap())
            .await?;

        Ok(pool)
    }
}
