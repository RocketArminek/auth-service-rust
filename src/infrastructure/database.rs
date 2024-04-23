use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Error, MySql, Pool};

pub async fn create_mysql_pool(database_url: &String) -> Result<Pool<MySql>, Error> {
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    Ok(pool)
}
