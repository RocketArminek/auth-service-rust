use crate::application::configuration::app::AppConfiguration;
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use chrono::{Duration, Utc};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::marker::PhantomData;
use std::ops::Add;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Expired,
    InvalidSignature,
    Malformed,
    WrongKind,
    EncodingFailed,
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
    secret: String,
    access_ttl: i64,
    refresh_ttl: i64,
    verification_ttl: i64,
    password_reset_ttl: i64,
}

impl TokenService {
    pub fn new(
        secret: String,
        access_ttl: i64,
        refresh_ttl: i64,
        verification_ttl: i64,
        password_reset_ttl: i64,
    ) -> Self {
        Self {
            secret,
            access_ttl,
            refresh_ttl,
            verification_ttl,
            password_reset_ttl,
        }
    }

    pub fn from_config(config: &AppConfiguration) -> Self {
        Self::new(
            config.secret(),
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
        let value = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
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
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )
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
