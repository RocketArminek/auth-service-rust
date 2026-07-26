use crate::application::configuration::app::AppConfiguration;
use crate::application::service::keystore::KeyMaterial;
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use crate::domain::keystore::KeyAlgorithm;
use chrono::{Duration, Utc};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::Add;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Expired,
    InvalidSignature,
    Malformed,
    WrongKind,
    UnknownKid,
    EncodingFailed,
    InvalidKeyMaterial,
    Unknown,
}

pub trait TokenKind {
    const TYPE: TokenType;
}

#[derive(Debug, Clone)]
pub struct Access;

#[derive(Debug, Clone)]
pub struct Refresh;

#[derive(Debug, Clone)]
pub struct Verification;

#[derive(Debug, Clone)]
pub struct PasswordReset;

impl TokenKind for Access {
    const TYPE: TokenType = TokenType::Access;
}

impl TokenKind for Refresh {
    const TYPE: TokenType = TokenType::Refresh;
}

impl TokenKind for Verification {
    const TYPE: TokenType = TokenType::Verification;
}

impl TokenKind for PasswordReset {
    const TYPE: TokenType = TokenType::Password;
}

#[derive(Debug, Clone)]
pub struct SignedToken<K: TokenKind> {
    pub value: String,
    pub expires_at: usize,
    kind: PhantomData<K>,
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: SignedToken<Access>,
    pub refresh_token: SignedToken<Refresh>,
}

#[derive(Debug, Clone)]
pub struct TypedClaims<K: TokenKind> {
    claims: Claims,
    kind: PhantomData<K>,
}

impl<K: TokenKind> TypedClaims<K> {
    pub fn user(&self) -> &UserDTO {
        &self.claims.user
    }

    pub fn into_user(self) -> UserDTO {
        self.claims.user
    }

    pub fn exp(&self) -> usize {
        self.claims.exp
    }
}

#[derive(Clone)]
pub struct TokenService {
    kid: String,
    signing_algorithm: Algorithm,
    encoding_key: Arc<EncodingKey>,
    decoding_keys: Arc<HashMap<String, (Algorithm, DecodingKey)>>,
    access_ttl: i64,
    refresh_ttl: i64,
    verification_ttl: i64,
    password_reset_ttl: i64,
}

impl TokenService {
    pub fn new(
        keys: &KeyMaterial,
        access_ttl: i64,
        refresh_ttl: i64,
        verification_ttl: i64,
        password_reset_ttl: i64,
    ) -> Result<Self, TokenError> {
        let signing_algorithm = jwt_algorithm(keys.active.algorithm());
        let encoding_key = match keys.active.algorithm() {
            KeyAlgorithm::EdDSA => EncodingKey::from_ed_der(keys.active.private_key_der()),
        };

        let mut decoding_keys = HashMap::new();
        for verifier in &keys.verifiers {
            let decoding_key = match verifier.algorithm {
                KeyAlgorithm::EdDSA => DecodingKey::from_ed_components(&verifier.public_key)
                    .map_err(|_| TokenError::InvalidKeyMaterial)?,
            };
            decoding_keys.insert(
                verifier.kid.clone(),
                (jwt_algorithm(verifier.algorithm), decoding_key),
            );
        }

        Ok(Self {
            kid: keys.active.kid().to_string(),
            signing_algorithm,
            encoding_key: Arc::new(encoding_key),
            decoding_keys: Arc::new(decoding_keys),
            access_ttl,
            refresh_ttl,
            verification_ttl,
            password_reset_ttl,
        })
    }

    pub fn from_config(config: &AppConfiguration, keys: &KeyMaterial) -> Result<Self, TokenError> {
        Self::new(
            keys,
            config.at_duration_in_seconds().to_signed(),
            config.rt_duration_in_seconds().to_signed(),
            config.vr_duration_in_seconds().to_signed(),
            config.rp_duration_in_seconds().to_signed(),
        )
    }

    pub fn issue<K: TokenKind>(&self, user: UserDTO) -> Result<SignedToken<K>, TokenError> {
        let expires_at = Utc::now()
            .add(Duration::seconds(self.ttl_for(&K::TYPE)))
            .timestamp() as usize;

        self.issue_with_exp(user, expires_at)
    }

    pub fn issue_with_exp<K: TokenKind>(
        &self,
        user: UserDTO,
        expires_at: usize,
    ) -> Result<SignedToken<K>, TokenError> {
        let claims = Claims::new(expires_at, user, K::TYPE);
        let mut header = Header::new(self.signing_algorithm);
        header.kid = Some(self.kid.clone());

        let value = encode(&header, &claims, &self.encoding_key)
            .map_err(|_| TokenError::EncodingFailed)?;

        Ok(SignedToken {
            value,
            expires_at,
            kind: PhantomData,
        })
    }

    pub fn issue_pair(&self, user: UserDTO) -> Result<TokenPair, TokenError> {
        let now = Utc::now();
        let at_exp = now.add(Duration::seconds(self.access_ttl)).timestamp() as usize;
        let rt_exp = now.add(Duration::seconds(self.refresh_ttl)).timestamp() as usize;

        Ok(TokenPair {
            access_token: self.issue_with_exp::<Access>(user.clone(), at_exp)?,
            refresh_token: self.issue_with_exp::<Refresh>(user, rt_exp)?,
        })
    }

    pub fn validate<K: TokenKind>(&self, token: &str) -> Result<TypedClaims<K>, TokenError> {
        let claims = self.decode(token)?;

        if claims.token_type != K::TYPE {
            return Err(TokenError::WrongKind);
        }

        Ok(TypedClaims {
            claims,
            kind: PhantomData,
        })
    }

    pub fn decode(&self, token: &str) -> Result<Claims, TokenError> {
        let header = decode_header(token).map_err(|_| TokenError::Malformed)?;
        let kid = header.kid.ok_or(TokenError::UnknownKid)?;
        let (algorithm, decoding_key) = self
            .decoding_keys
            .get(&kid)
            .ok_or(TokenError::UnknownKid)?;

        decode::<Claims>(token, decoding_key, &Validation::new(*algorithm))
            .map(|decoded| decoded.claims)
            .map_err(|e| match e.kind() {
                ErrorKind::ExpiredSignature => TokenError::Expired,
                ErrorKind::InvalidSignature => TokenError::InvalidSignature,
                ErrorKind::InvalidToken => TokenError::Malformed,
                _ => TokenError::Unknown,
            })
    }

    fn ttl_for(&self, token_type: &TokenType) -> i64 {
        match token_type {
            TokenType::Access => self.access_ttl,
            TokenType::Refresh => self.refresh_ttl,
            TokenType::Verification => self.verification_ttl,
            TokenType::Password => self.password_reset_ttl,
        }
    }
}

fn jwt_algorithm(algorithm: KeyAlgorithm) -> Algorithm {
    match algorithm {
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
    }
}
