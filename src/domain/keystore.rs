use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use sha2::{Digest, Sha256};
use sqlx::FromRow;

const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    InvalidKeyEncryptionKey(String),
    SealFailed,
    UnsealFailed,
    KeyGenerationFailed,
    RetiredKeyUnsealed,
    UnsupportedAlgorithm(String),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::InvalidKeyEncryptionKey(reason) => {
                write!(f, "Invalid key encryption key: {}", reason)
            }
            KeystoreError::SealFailed => write!(f, "Failed to seal private key"),
            KeystoreError::UnsealFailed => write!(f, "Failed to unseal private key"),
            KeystoreError::KeyGenerationFailed => write!(f, "Failed to generate signing key"),
            KeystoreError::RetiredKeyUnsealed => {
                write!(f, "Retired key cannot be used for signing")
            }
            KeystoreError::UnsupportedAlgorithm(alg) => {
                write!(f, "Unsupported key algorithm: {}", alg)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    EdDSA,
}

impl KeyAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAlgorithm::EdDSA => "EdDSA",
        }
    }
}

impl TryFrom<&str> for KeyAlgorithm {
    type Error = KeystoreError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "EdDSA" => Ok(KeyAlgorithm::EdDSA),
            other => Err(KeystoreError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

#[derive(Clone)]
pub struct KeyEncryptionKey([u8; 32]);

impl KeyEncryptionKey {
    pub fn from_base64(value: &str) -> Result<Self, KeystoreError> {
        let bytes = STANDARD.decode(value.trim()).map_err(|_| {
            KeystoreError::InvalidKeyEncryptionKey("not valid base64".to_string())
        })?;

        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            KeystoreError::InvalidKeyEncryptionKey("must decode to exactly 32 bytes".to_string())
        })?;

        Ok(Self(bytes))
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.0).map_err(|_| KeystoreError::SealFailed)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| KeystoreError::SealFailed)?;

        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| KeystoreError::SealFailed)?;

        let mut sealed = nonce.to_vec();
        sealed.extend(ciphertext);

        Ok(sealed)
    }

    pub fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        if sealed.len() <= NONCE_LEN {
            return Err(KeystoreError::UnsealFailed);
        }

        let cipher =
            Aes256Gcm::new_from_slice(&self.0).map_err(|_| KeystoreError::UnsealFailed)?;
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);

        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| KeystoreError::UnsealFailed)
    }
}

#[derive(Clone)]
pub struct SigningKey {
    kid: String,
    algorithm: KeyAlgorithm,
    public_key: String,
    private_key_der: Vec<u8>,
}

impl SigningKey {
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self, KeystoreError> {
        match algorithm {
            KeyAlgorithm::EdDSA => {
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed)
                    .map_err(|_| KeystoreError::KeyGenerationFailed)?;

                let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
                let private_key_der = key
                    .to_pkcs8_der()
                    .map_err(|_| KeystoreError::KeyGenerationFailed)?
                    .as_bytes()
                    .to_vec();

                Ok(Self {
                    kid: ed25519_thumbprint(&public_key),
                    algorithm,
                    public_key,
                    private_key_der,
                })
            }
        }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            kid: self.kid.clone(),
            algorithm: self.algorithm,
            public_key: self.public_key.clone(),
        }
    }

    pub fn seal(&self, kek: &KeyEncryptionKey) -> Result<SigningKeyRecord, KeystoreError> {
        Ok(SigningKeyRecord {
            kid: self.kid.clone(),
            alg: self.algorithm.as_str().to_string(),
            public_key: self.public_key.clone(),
            sealed_private_key: kek.seal(&self.private_key_der)?,
            created_at: Utc::now(),
            retired_at: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub kid: String,
    pub algorithm: KeyAlgorithm,
    pub public_key: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct SigningKeyRecord {
    pub kid: String,
    pub alg: String,
    pub public_key: String,
    pub sealed_private_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

impl SigningKeyRecord {
    pub fn is_active(&self) -> bool {
        self.retired_at.is_none()
    }

    pub fn unseal(&self, kek: &KeyEncryptionKey) -> Result<SigningKey, KeystoreError> {
        if !self.is_active() {
            return Err(KeystoreError::RetiredKeyUnsealed);
        }

        Ok(SigningKey {
            kid: self.kid.clone(),
            algorithm: KeyAlgorithm::try_from(self.alg.as_str())?,
            public_key: self.public_key.clone(),
            private_key_der: kek.unseal(&self.sealed_private_key)?,
        })
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, KeystoreError> {
        Ok(VerifyingKey {
            kid: self.kid.clone(),
            algorithm: KeyAlgorithm::try_from(self.alg.as_str())?,
            public_key: self.public_key.clone(),
        })
    }
}

fn ed25519_thumbprint(x: &str) -> String {
    let jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, x);
    URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))
}
