use sqlx::migrate::{MigrateDatabase, MigrateError};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::sqlx_macros::migrate;
use sqlx::{Error, MySql, Pool, Sqlite};
use std::env;

pub enum DatabaseEngine {
    Sqlite,
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
            Ok(_) => {
                tracing::info!("Database migration completed successfully");
            }
            Err(e) => {
                tracing::error!("Failed to migrate database: {}", e);
                panic!("Failed to migrate database");
            }
        }
    }
}

impl Into<Pool<MySql>> for DatabasePool {
    fn into(self) -> Pool<MySql> {
        match self {
            DatabasePool::MySql(pool) => pool,
            DatabasePool::Sqlite(_) => panic!("Cannot convert mysql into sqlite"),
        }
    }
}

impl Into<Pool<Sqlite>> for DatabasePool {
    fn into(self) -> Pool<Sqlite> {
        match self {
            DatabasePool::MySql(_) => panic!("Cannot convert sqlite into mysql"),
            DatabasePool::Sqlite(pool) => pool,
        }
    }
}

impl DatabaseEngine {
    pub fn to_string(&self) -> String {
        match self {
            DatabaseEngine::Sqlite => "sqlite".to_string(),
            DatabaseEngine::Mysql => "mysql".to_string(),
        }
    }
}

impl Into<String> for DatabaseEngine {
    fn into(self) -> String {
        self.to_string()
    }
}

impl TryFrom<String> for DatabaseEngine {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "sqlite" => Ok(DatabaseEngine::Sqlite),
            "mysql" => Ok(DatabaseEngine::Mysql),
            _ => Err(format!("Unknown database type: {}", value)),
        }
    }
}

impl Default for DatabaseEngine {
    fn default() -> Self {
        DatabaseEngine::Mysql
    }
}

pub fn get_database_engine() -> DatabaseEngine {
    let db_url = env::var("DATABASE_URL");
    match db_url {
        Ok(db_url) => {
            if db_url.is_empty() {
                panic!("DATABASE_URL is empty");
            }
            let url_lower = db_url.to_lowercase();
            match url_lower {
                url if url.starts_with("sqlite:") => DatabaseEngine::Sqlite,
                url if url.starts_with("mysql:") => DatabaseEngine::Mysql,
                _ => DatabaseEngine::default(),
            }
        }
        Err(_) => env::var("DATABASE_ENGINE")
            .unwrap_or_default()
            .try_into()
            .unwrap_or_default(),
    }
}

pub async fn create_pool(database_engine: &DatabaseEngine) -> Result<DatabasePool, Error> {
    match database_engine {
        DatabaseEngine::Sqlite => Ok(DatabasePool::Sqlite(
            create_sqlite_pool(&get_sqlite_db_url().unwrap()).await?,
        )),
        DatabaseEngine::Mysql => Ok(DatabasePool::MySql(
            create_mysql_pool(&get_mysql_database_url().unwrap()).await?,
        )),
    }
}

pub fn get_sqlite_db_url() -> Result<String, String> {
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        let path = env::var("SQLITE_PATH").expect("SQLITE_PATH environment variable not set");
        format!("sqlite://{}", path)
    });

    if database_url.is_empty() {
        return Err("DATABASE_URL is empty".to_string());
    }

    Ok(database_url)
}

pub async fn create_sqlite_pool(database_url: &str) -> Result<Pool<Sqlite>, Error> {
    if !Sqlite::database_exists(database_url).await? {
        Sqlite::create_database(database_url).await?;
        tracing::info!(
            "Database does not exists. Database created for {}",
            database_url
        );
    }

    let max_connections = env::var("DATABASE_MAX_CONNECTIONS")
        .unwrap_or("5".to_string())
        .parse()
        .unwrap_or(5);

    let timeout_ms = env::var("DATABASE_TIMEOUT_MS")
        .unwrap_or("50".to_string())
        .parse()
        .unwrap_or(50);

    SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_millis(timeout_ms))
        .connect(&database_url)
        .await
}

pub fn get_mysql_database_url() -> Result<String, String> {
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        let user = env::var("DATABASE_USER").expect("DATABASE_USER is not set");
        let password = env::var("DATABASE_PASSWORD").expect("DATABASE_PASSWORD is not set");
        let host = env::var("DATABASE_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port = env::var("DATABASE_PORT").unwrap_or_else(|_| "3306".to_string());
        let name = env::var("DATABASE_NAME").expect("DATABASE_NAME is not set");

        format!("mysql://{}:{}@{}:{}/{}", user, password, host, port, name)
    });

    if database_url.is_empty() {
        return Err("DATABASE_URL is empty".to_string());
    }

    Ok(database_url)
}

pub async fn create_mysql_pool(database_url: &str) -> Result<Pool<MySql>, Error> {
    if !MySql::database_exists(database_url).await? {
        MySql::create_database(database_url).await?;
        tracing::info!(
            "Database does not exists. Database created {}",
            database_url.split("/").last().unwrap_or("")
        );
    }

    let max_connections = env::var("DATABASE_MAX_CONNECTIONS")
        .unwrap_or("5".to_string())
        .parse()
        .unwrap_or(5);

    let timeout_ms = env::var("DATABASE_TIMEOUT_MS")
        .unwrap_or("500".to_string())
        .parse()
        .unwrap_or(500);

    MySqlPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_millis(timeout_ms))
        .connect(&database_url)
        .await
}
