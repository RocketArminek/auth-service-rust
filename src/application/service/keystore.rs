use crate::domain::keystore::{
    KeyAlgorithm, KeyEncryptionKey, KeystoreError, SigningKey, VerifyingKey,
};
use crate::infrastructure::repository::RepositoryError;
use crate::infrastructure::signing_key_repository::SigningKeyRepository;

#[derive(Clone)]
pub struct KeyMaterial {
    pub active: SigningKey,
    pub verifiers: Vec<VerifyingKey>,
}

#[derive(Debug)]
pub enum KeystoreInitError {
    Keystore(KeystoreError),
    Repository(RepositoryError),
    NoActiveKey,
}

impl std::fmt::Display for KeystoreInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreInitError::Keystore(e) => write!(f, "{}", e),
            KeystoreInitError::Repository(e) => write!(f, "{}", e),
            KeystoreInitError::NoActiveKey => write!(f, "No active signing key in keystore"),
        }
    }
}

impl From<KeystoreError> for KeystoreInitError {
    fn from(error: KeystoreError) -> Self {
        KeystoreInitError::Keystore(error)
    }
}

impl From<RepositoryError> for KeystoreInitError {
    fn from(error: RepositoryError) -> Self {
        KeystoreInitError::Repository(error)
    }
}

pub async fn initialize_keystore(
    repository: &SigningKeyRepository,
    kek: &KeyEncryptionKey,
    algorithm: KeyAlgorithm,
) -> Result<KeyMaterial, KeystoreInitError> {
    let mut records = repository.find_all().await?;

    if !records.iter().any(|record| record.is_active()) {
        let generated = SigningKey::generate(algorithm)?;

        match repository.insert(&generated.seal(kek)?).await {
            Ok(()) => {
                tracing::info!(kid = generated.kid(), "Generated new signing key");
            }
            Err(RepositoryError::Conflict(_)) => {
                tracing::info!("Another instance generated the signing key first");
            }
            Err(e) => return Err(e.into()),
        }

        records = repository.find_all().await?;
    }

    let active = records
        .iter()
        .find(|record| record.is_active())
        .ok_or(KeystoreInitError::NoActiveKey)?
        .unseal(kek)?;

    let verifiers = records
        .iter()
        .map(|record| record.verifying_key())
        .collect::<Result<Vec<_>, _>>()?;

    Ok(KeyMaterial { active, verifiers })
}
