use crate::domain::keystore::SigningKeyRecord;
use crate::infrastructure::database::DatabasePool;
use crate::infrastructure::mysql_signing_key_repository::MysqlSigningKeyRepository;
use crate::infrastructure::repository::RepositoryError;
use crate::infrastructure::sqlite_signing_key_repository::SqliteSigningKeyRepository;

#[derive(Clone)]
pub enum SigningKeyRepository {
    Mysql(MysqlSigningKeyRepository),
    Sqlite(SqliteSigningKeyRepository),
}

impl SigningKeyRepository {
    pub fn new(pool: &DatabasePool) -> Self {
        match pool {
            DatabasePool::MySql(pool) => Self::Mysql(MysqlSigningKeyRepository::new(pool.clone())),
            DatabasePool::Sqlite(pool) => {
                Self::Sqlite(SqliteSigningKeyRepository::new(pool.clone()))
            }
        }
    }

    pub async fn find_all(&self) -> Result<Vec<SigningKeyRecord>, RepositoryError> {
        match self {
            SigningKeyRepository::Mysql(repo) => repo.find_all().await,
            SigningKeyRepository::Sqlite(repo) => repo.find_all().await,
        }
    }

    pub async fn insert(&self, record: &SigningKeyRecord) -> Result<(), RepositoryError> {
        match self {
            SigningKeyRepository::Mysql(repo) => repo.insert(record).await,
            SigningKeyRepository::Sqlite(repo) => repo.insert(record).await,
        }
    }
}
