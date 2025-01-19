use crate::infrastructure::database::DatabaseEngine;
use std::collections::HashMap;
use std::env;

pub struct DatabaseConfigurationBuilder {
    pub database_engine: Option<DatabaseEngine>,
    pub database_url: Option<String>,
    pub database_max_connections: Option<u32>,
    pub database_timeout_ms: Option<u64>,
}

impl Default for DatabaseConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
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
        let database_url = env::var(EnvNames::DATABASE_URL);

        self.database_engine = match database_url.clone() {
            Ok(url) if !url.is_empty() => match url.to_lowercase() {
                url if url.starts_with("sqlite:") => Some(DatabaseEngine::Sqlite),
                url if url.starts_with("mysql:") => Some(DatabaseEngine::Mysql),
                _ => None,
            },
            _ => env::var(EnvNames::DATABASE_ENGINE)
                .ok()
                .map(|v| v.try_into().unwrap_or_default()),
        };

        self.database_max_connections = env::var(EnvNames::DATABASE_MAX_CONNECTIONS)
            .ok()
            .map(|v| v.parse::<u32>().unwrap());
        self.database_timeout_ms = env::var(EnvNames::DATABASE_TIMEOUT_MS)
            .ok()
            .map(|v| v.parse::<u64>().unwrap());

        match self.database_engine {
            Some(DatabaseEngine::Mysql) => {
                self.database_url = self.get_mysql_database_url(database_url);
            }
            Some(DatabaseEngine::Sqlite) => {
                self.database_url = self.get_sqlite_database_url(database_url);
            }
            None => {}
        }

        self
    }

    pub fn build(&self) -> DatabaseConfiguration {
        DatabaseConfiguration::new(
            self.database_engine.clone().unwrap_or_default(),
            self.database_url.clone().unwrap_or_default(),
            self.database_max_connections.unwrap_or(5),
            self.database_timeout_ms.unwrap_or(500),
        )
    }

    fn get_mysql_database_url(
        &self,
        database_url: Result<String, env::VarError>,
    ) -> Option<String> {
        match database_url {
            Ok(url) if !url.is_empty() => Some(url),
            _ => {
                let user = env::var(EnvNames::DATABASE_USER).ok();
                let password = env::var(EnvNames::DATABASE_PASSWORD).ok();
                let host = env::var(EnvNames::DATABASE_HOST).ok();
                let port = env::var(EnvNames::DATABASE_PORT).ok();
                let name = env::var(EnvNames::DATABASE_NAME).ok();

                match (user, password, host, port, name) {
                    (Some(user), Some(password), Some(host), Some(port), Some(name)) => Some(
                        format!("mysql://{}:{}@{}:{}/{}", user, password, host, port, name),
                    ),
                    _ => None,
                }
            }
        }
    }

    fn get_sqlite_database_url(
        &self,
        database_url: Result<String, env::VarError>,
    ) -> Option<String> {
        match database_url {
            Ok(url) if !url.is_empty() => Some(url),
            _ => env::var(EnvNames::SQLITE_PATH)
                .ok()
                .map(|path| format!("sqlite://{}", path)),
        }
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

    pub fn envs(&self) -> HashMap<String, String> {
        let mut envs = HashMap::new();

        envs.insert(EnvNames::DATABASE_URL.to_owned(), self.database_url.clone());
        envs.insert(
            EnvNames::DATABASE_ENGINE.to_owned(),
            self.database_engine.to_string(),
        );
        envs.insert(
            EnvNames::DATABASE_MAX_CONNECTIONS.to_owned(),
            self.database_max_connections.to_string(),
        );
        envs.insert(
            EnvNames::DATABASE_TIMEOUT_MS.to_owned(),
            self.database_timeout_ms.to_string(),
        );

        envs
    }
}

pub struct EnvNames;

impl EnvNames {
    pub const DATABASE_URL: &'static str = "DATABASE_URL";
    pub const DATABASE_ENGINE: &'static str = "DATABASE_ENGINE";
    pub const DATABASE_MAX_CONNECTIONS: &'static str = "DATABASE_MAX_CONNECTIONS";
    pub const DATABASE_TIMEOUT_MS: &'static str = "DATABASE_TIMEOUT_MS";

    pub const DATABASE_USER: &'static str = "DATABASE_USER";
    pub const DATABASE_PASSWORD: &'static str = "DATABASE_PASSWORD";
    pub const DATABASE_HOST: &'static str = "DATABASE_HOST";
    pub const DATABASE_PORT: &'static str = "DATABASE_PORT";
    pub const DATABASE_NAME: &'static str = "DATABASE_NAME";

    pub const SQLITE_PATH: &'static str = "SQLITE_PATH";
}
