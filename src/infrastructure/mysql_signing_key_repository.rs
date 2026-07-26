use crate::domain::keystore::SigningKeyRecord;
use crate::infrastructure::repository::RepositoryError;
use sqlx::{MySql, Pool, query, query_as};

#[derive(Clone)]
pub struct MysqlSigningKeyRepository {
    pool: Pool<MySql>,
}

impl MysqlSigningKeyRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }

    pub async fn find_all(&self) -> Result<Vec<SigningKeyRecord>, RepositoryError> {
        let records = query_as::<_, SigningKeyRecord>(
            "SELECT kid, alg, public_key, sealed_private_key, created_at, retired_at FROM signing_keys ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    pub async fn insert(&self, record: &SigningKeyRecord) -> Result<(), RepositoryError> {
        query(
            "INSERT INTO signing_keys (kid, alg, public_key, sealed_private_key, created_at, retired_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.kid)
        .bind(&record.alg)
        .bind(&record.public_key)
        .bind(&record.sealed_private_key)
        .bind(record.created_at)
        .bind(record.retired_at)
        .execute(&self.pool)
        .await
        .map_err(unique_violation_as_conflict)?;

        Ok(())
    }
}

fn unique_violation_as_conflict(error: sqlx::Error) -> RepositoryError {
    if error
        .as_database_error()
        .is_some_and(|e| e.is_unique_violation())
    {
        return RepositoryError::Conflict("Active signing key already exists".to_string());
    }

    error.into()
}
