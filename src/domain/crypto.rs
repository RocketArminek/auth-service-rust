use crate::domain::error::UserError;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use bcrypt::DEFAULT_COST;
use std::collections::HashMap;
use std::sync::OnceLock;

pub trait Hasher {
    fn hash_password(&self, password: &str) -> Result<String, UserError>;
    fn verify_password(&self, password: &str, hash: &str) -> bool;
}

pub struct SchemeAwareHasher {
    algorithms: HashMap<HashingScheme, Box<dyn Hasher>>,
    pub current_scheme: HashingScheme,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum HashingScheme {
    Argon2,
    Bcrypt,
    BcryptLow,
}

impl HashingScheme {
    pub fn to_string(&self) -> String {
        match self {
            HashingScheme::Argon2 => "argon2".to_string(),
            HashingScheme::Bcrypt => "bcrypt".to_string(),
            HashingScheme::BcryptLow => "bcrypt_low".to_string(),
        }
    }

    pub fn from_string(scheme: String) -> Result<Self, UserError> {
        match scheme.as_str() {
            "argon2" => Ok(HashingScheme::Argon2),
            "bcrypt" => Ok(HashingScheme::Bcrypt),
            "bcrypt_low" => Ok(HashingScheme::BcryptLow),
            _ => Err(UserError::SchemeNotSupported),
        }
    }
}

impl SchemeAwareHasher {
    pub fn default() -> Self {
        let mut hashers: HashMap<HashingScheme, Box<dyn Hasher>> = HashMap::new();
        hashers.insert(HashingScheme::Argon2, Box::new(Argon2Hasher::new()));
        hashers.insert(HashingScheme::Bcrypt, Box::new(BcryptHasher::default()));
        hashers.insert(HashingScheme::BcryptLow, Box::new(BcryptHasher::low_cost()));

        SchemeAwareHasher {
            algorithms: hashers,
            current_scheme: HashingScheme::BcryptLow,
        }
    }

    pub fn with_scheme(scheme: HashingScheme) -> Self {
        let mut hashers: HashMap<HashingScheme, Box<dyn Hasher>> = HashMap::new();
        hashers.insert(HashingScheme::Argon2, Box::new(Argon2Hasher::new()));
        hashers.insert(HashingScheme::Bcrypt, Box::new(BcryptHasher::default()));
        hashers.insert(HashingScheme::BcryptLow, Box::new(BcryptHasher::low_cost()));

        SchemeAwareHasher {
            algorithms: hashers,
            current_scheme: scheme,
        }
    }

    pub fn with_scheme_and_hashers(
        scheme: HashingScheme,
        hashers: HashMap<HashingScheme, Box<dyn Hasher>>,
    ) -> Self {
        SchemeAwareHasher {
            algorithms: hashers,
            current_scheme: scheme,
        }
    }

    pub fn add_hasher(&mut self, name: HashingScheme, hasher: impl Hasher + 'static) {
        self.algorithms.insert(name, Box::new(hasher));
    }

    pub fn is_password_outdated(&self, hash: &str) -> bool {
        let parts = self.extract_scheme_and_hash(hash);

        parts.is_some_and(|(scheme, _)| scheme != self.current_scheme)
    }

    fn extract_scheme_and_hash<'a>(&'a self, hash: &'a str) -> Option<(HashingScheme, &'a str)> {
        let parts: Vec<&str> = hash.splitn(2, '.').collect();
        if parts.len() != 2 {
            return None;
        }
        let scheme = HashingScheme::from_string(parts[0].to_string()).ok()?;
        let hash = parts[1];

        Some((scheme, hash))
    }
}

impl Hasher for SchemeAwareHasher {
    fn hash_password(&self, password: &str) -> Result<String, UserError> {
        let hasher = self.algorithms.get(&self.current_scheme);

        match hasher {
            Some(hasher) => {
                let hashed_password = hasher.hash_password(password)?;
                Ok(format!(
                    "{}.{}",
                    self.current_scheme.to_string(),
                    hashed_password
                ))
            }
            None => Err(UserError::EncryptionFailed),
        }
    }

    fn verify_password(&self, password: &str, hash: &str) -> bool {
        let parts = self.extract_scheme_and_hash(hash);

        parts.is_some_and(|parts| {
            let hasher = self.algorithms.get(&parts.0);

            match hasher {
                Some(hasher) => hasher.verify_password(password, parts.1),
                None => false,
            }
        })
    }
}

pub struct Argon2Hasher {
    argon2: Argon2<'static>,
}

impl Argon2Hasher {
    pub fn new() -> Self {
        Argon2Hasher {
            argon2: get_argon2().clone(),
        }
    }
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Argon2Hasher {
    fn hash_password(&self, password: &str) -> Result<String, UserError> {
        let salt = SaltString::generate(&mut OsRng);

        self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| UserError::EncryptionFailed)
            .map(|hash| hash.to_string())
    }

    fn verify_password(&self, password: &str, hash: &str) -> bool {
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(result) => result,
            Err(_) => return false,
        };

        self.argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

pub struct BcryptHasher {
    cost: u32,
}

impl BcryptHasher {
    pub fn new(cost: u32) -> Self {
        BcryptHasher { cost }
    }

    pub fn low_cost() -> Self {
        BcryptHasher::new(4)
    }

    pub fn max_cost() -> Self {
        BcryptHasher::new(31)
    }
}

impl Default for BcryptHasher {
    fn default() -> Self {
        BcryptHasher::new(DEFAULT_COST)
    }
}

impl Hasher for BcryptHasher {
    fn hash_password(&self, password: &str) -> Result<String, UserError> {
        bcrypt::hash(password, self.cost).map_err(|_| UserError::EncryptionFailed)
    }

    fn verify_password(&self, password: &str, hash: &str) -> bool {
        bcrypt::verify(password, hash).unwrap_or(false)
    }
}

fn get_argon2() -> &'static Argon2<'static> {
    static INSTANCE: OnceLock<Argon2> = OnceLock::new();
    INSTANCE.get_or_init(|| Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default()))
}
