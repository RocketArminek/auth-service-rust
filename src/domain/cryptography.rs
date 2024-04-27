use crate::domain::error::Error;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

pub trait Hasher {
    fn hash_password(&self, password: &str) -> Result<String, Error>;
    fn verify_password(&self, password: &str, hash: &str) -> bool;
}

pub struct Argon2Hasher {}

impl Argon2Hasher {
    pub fn new() -> Self {
        Argon2Hasher {}
    }
}

impl Hasher for Argon2Hasher {
    fn hash_password(&self, password: &str) -> Result<String, Error> {
        let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
        let salt = SaltString::generate(&mut OsRng);

        hasher
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| Error::EncryptionFailed)
            .map(|hash| hash.to_string())
    }

    fn verify_password(&self, password: &str, hash: &str) -> bool {
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(result) => result,
            Err(_) => return false,
        };

        let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());

        hasher
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}
