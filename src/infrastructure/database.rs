use crate::application::configuration::database::DatabaseConfiguration;
use crate::infrastructure::utils::retry_with_backoff;
use sqlx::migrate::{MigrateDatabase, MigrateError};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::sqlx_macros::migrate;
use sqlx::{Error, MySql, Pool, Sqlite};
use std::fmt::Display;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub enum DatabaseEngine {
    Sqlite,
    #[default]
    Mysql,
}

#[derive(Clone)]
pub enum DatabasePool {
    MySql(Pool<MySql>),
    Sqlite(Pool<Sqlite>),
}

impl DatabasePool {
    pub async fn migrate(&self) {
        match self {
            DatabasePool::MySql(pool) => self.migrate_mysql(pool).await,
            DatabasePool::Sqlite(pool) => self.migrate_sqlite(pool).await,
        }
    }

    async fn migrate_sqlite(&self, pool: &Pool<Sqlite>) {
        self.handle_migration_result(migrate!("./migrations/sqlite").run(pool).await)
    }

    async fn migrate_mysql(&self, pool: &Pool<MySql>) {
        self.handle_migration_result(migrate!("./migrations/mysql").run(pool).await)
    }

    fn handle_migration_result(&self, r: Result<(), MigrateError>) {
        match r {
            Ok(_) => match self {
                DatabasePool::MySql(_) => {
                    tracing::info!("Mysql database migration completed successfully")
                }
                DatabasePool::Sqlite(_) => {
                    tracing::info!("Sqlite database migration completed successfully")
                }
            },
            Err(e) => {
                tracing::error!("Failed to migrate database: {}", e);
                panic!("Failed to migrate database");
            }
        }
    }
}

impl From<DatabasePool> for Pool<MySql> {
    fn from(pool: DatabasePool) -> Self {
        match pool {
            DatabasePool::MySql(pool) => pool,
            DatabasePool::Sqlite(_) => panic!("Cannot convert mysql into sqlite"),
        }
    }
}

impl From<DatabasePool> for Pool<Sqlite> {
    fn from(pool: DatabasePool) -> Self {
        match pool {
            DatabasePool::MySql(_) => panic!("Cannot convert mysql into sqlite"),
            DatabasePool::Sqlite(pool) => pool,
        }
    }
}

impl Display for DatabaseEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseEngine::Sqlite => write!(f, "sqlite"),
            DatabaseEngine::Mysql => write!(f, "mysql"),
        }
    }
}

impl From<DatabaseEngine> for String {
    fn from(value: DatabaseEngine) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for DatabaseEngine {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "sqlite" => Ok(DatabaseEngine::Sqlite),
            "mysql" => Ok(DatabaseEngine::Mysql),
            _ => Err(format!("Unknown database type: {}", value)),
        }
    }
}

pub async fn create_pool(config: &DatabaseConfiguration) -> Result<DatabasePool, Error> {
    match config.database_engine() {
        DatabaseEngine::Sqlite => Ok(DatabasePool::Sqlite(
            create_sqlite_pool(
                config.database_url(),
                config.database_max_connections(),
                config.database_timeout_ms(),
            )
            .await?,
        )),
        DatabaseEngine::Mysql => Ok(DatabasePool::MySql(
            create_mysql_pool(
                config.database_url(),
                config.database_max_connections(),
                config.database_timeout_ms(),
            )
            .await?,
        )),
    }
}

pub async fn create_sqlite_pool(
    database_url: &str,
    max_connections: u32,
    timeout_ms: u64,
) -> Result<Pool<Sqlite>, Error> {
    retry_with_backoff(
        || async {
            if !Sqlite::database_exists(database_url).await? {
                Sqlite::create_database(database_url).await?;
                tracing::info!(
                    "Database does not exists. Database created for {}",
                    database_url
                );
            }

            let pool = SqlitePoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(Duration::from_millis(timeout_ms))
                .after_connect(|conn, _| Box::pin(async {
                    sqlx::query("PRAGMA journal_mode=WAL").execute(&mut *conn).await?;
                    sqlx::query("PRAGMA synchronous=NORMAL").execute(&mut *conn).await?;
                    sqlx::query("PRAGMA busy_timeout=30000").execute(&mut *conn).await?;
                    sqlx::query("PRAGMA cache_size=-8000").execute(&mut *conn).await?;
                    sqlx::query("PRAGMA foreign_keys=ON").execute(&mut *conn).await?;
                    sqlx::query("PRAGMA temp_store=MEMORY").execute(&mut *conn).await?;
                    sqlx::query("PRAGMA mmap_size=30000000000").execute(&mut *conn).await?;
                    sqlx::query("PRAGMA wal_autocheckpoint=1000").execute(&mut *conn).await?;
                    sqlx::query("PRAGMA page_size=4096").execute(&mut *conn).await?;
                    Ok(())
                }))
                .connect(database_url)
                .await?;

            Ok(pool)
        },
        "Sqlite",
        5,
        Duration::from_millis(1000),
        true,
    )
    .await
}

pub async fn create_mysql_pool(
    database_url: &str,
    max_connections: u32,
    timeout_ms: u64,
) -> Result<Pool<MySql>, Error> {
    retry_with_backoff(
        || async {
            if !MySql::database_exists(database_url).await? {
                MySql::create_database(database_url).await?;
                tracing::info!(
                    "Database does not exists. Database created {}",
                    database_url.split("/").last().unwrap_or("")
                );
            }

            MySqlPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(Duration::from_millis(timeout_ms))
                .connect(database_url)
                .await
        },
        "MySql",
        5,
        Duration::from_millis(500),
        true,
    )
    .await
}
