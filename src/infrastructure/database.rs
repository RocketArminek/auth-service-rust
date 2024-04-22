use std::env;
use sqlx::{Error, MySql, Pool};
use sqlx::mysql::MySqlPoolOptions;

pub async fn create_mysql_pool() -> Result<Pool<MySql>, Error> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    Ok(pool)
}
