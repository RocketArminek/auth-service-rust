use auth_service::infrastructure::database::DatabasePool;
use sqlx::migrate::MigrateDatabase;
use sqlx::{MySql, Sqlite};

pub async fn drop_database(database_pool: &DatabasePool, database_url: &str) {
    match database_pool {
        DatabasePool::MySql(_) => {
            MySql::drop_database(database_url).await.unwrap();
        }
        DatabasePool::Sqlite(_) => {
            Sqlite::drop_database(database_url).await.unwrap();
        }
    }
}
