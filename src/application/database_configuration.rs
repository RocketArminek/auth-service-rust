use std::env;
use crate::infrastructure::database::DatabaseEngine;

pub struct DatabaseConfigurationBuilder {
    pub database_engine: Option<DatabaseEngine>,
    pub database_url: Option<String>,
    pub database_max_connections: Option<u32>,
    pub database_timeout_ms: Option<u64>,
}

impl DatabaseConfigurationBuilder {
    pub fn new() -> Self {
        DatabaseConfigurationBuilder {
            database_engine: None,
            database_url: None,
            database_max_connections: None,
            database_timeout_ms: None,
        }
    }

    pub fn database_engine(&mut self, database_engine: DatabaseEngine) -> &mut Self {
        self.database_engine = Some(database_engine);
        self
    }

    pub fn database_url(&mut self, database_url: String) -> &mut Self {
        self.database_url = Some(database_url);
        self
    }

    pub fn database_max_connections(&mut self, database_max_connections: u32) -> &mut Self {
        self.database_max_connections = Some(database_max_connections);
        self
    }

    pub fn database_timeout_ms(&mut self, database_timeout_ms: u64) -> &mut Self {
        self.database_timeout_ms = Some(database_timeout_ms);
        self
    }

    pub fn load_env(&mut self) -> &mut Self {
        let database_url = env::var("DATABASE_URL");

        self.database_engine = match database_url.clone() {
            Ok(url) if !url.is_empty() => match url.to_lowercase() {
                url if url.starts_with("sqlite:") => Some(DatabaseEngine::Sqlite),
                url if url.starts_with("mysql:") => Some(DatabaseEngine::Mysql),
                _ => None,
            },
            _ => env::var("DATABASE_ENGINE")
                .ok()
                .map(|v| v.try_into().unwrap_or_default())
        };

        self.database_max_connections = env::var("DATABASE_MAX_CONNECTIONS").ok()
            .map(|v| v.parse::<u32>().unwrap());
        self.database_timeout_ms = env::var("DATABASE_TIMEOUT_MS").ok()
            .map(|v| v.parse::<u64>().unwrap());

        match self.database_engine {
            None => {}
            Some(DatabaseEngine::Mysql) => {
                match database_url {
                    Ok(url) if !url.is_empty() => self.database_url = Some(url),
                    _ => {
                        let user = env::var("DATABASE_USER").ok();
                        let password = env::var("DATABASE_PASSWORD").ok();
                        let host = env::var("DATABASE_HOST").ok();
                        let port = env::var("DATABASE_PORT").ok();
                        let name = env::var("DATABASE_NAME").ok();

                        match (user, password, host, port, name) {
                            (
                                Some(user),
                                Some(password),
                                Some(host),
                                Some(port),
                                Some(name)
                            ) =>
                                self.database_url = Some(
                                    format!(
                                        "mysql://{}:{}@{}:{}/{}",
                                        user,
                                        password,
                                        host,
                                        port,
                                        name,
                                    )
                                ),
                            _ => {}
                        }
                    }
                }
            }
            Some(DatabaseEngine::Sqlite) => {
                match database_url {
                    Ok(url) if !url.is_empty() => self.database_url = Some(url),
                    _ => {
                        self.database_url = env::var("SQLITE_PATH").ok()
                            .map(|path| format!("sqlite://{}", path));
                    }
                }
            }
        }

        self
    }

    pub fn build(&self) -> DatabaseConfiguration {
        DatabaseConfiguration::new(
            self.database_engine.clone().unwrap_or_default(),
            self.database_url.clone().unwrap_or_default(),
            self.database_max_connections.unwrap_or(5),
            self.database_timeout_ms.unwrap_or(50),
        )
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfiguration {
    database_engine: DatabaseEngine,
    database_url: String,
    database_max_connections: u32,
    database_timeout_ms: u64,
}

impl DatabaseConfiguration {
    pub fn new(
        database_engine: DatabaseEngine,
        database_url: String,
        database_max_connections: u32,
        database_timeout_ms: u64,
    ) -> Self {
        DatabaseConfiguration {
            database_engine,
            database_url,
            database_max_connections,
            database_timeout_ms,
        }
    }

    pub fn database_engine(&self) -> DatabaseEngine {
        self.database_engine.clone()
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub fn database_max_connections(&self) -> u32 {
        self.database_max_connections
    }

    pub fn database_timeout_ms(&self) -> u64 {
        self.database_timeout_ms
    }
}
