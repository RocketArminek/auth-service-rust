use crate::application::configuration::app::AppConfiguration;
use crate::application::service::stateful_auth_service::StatefulAuthService;
use crate::application::service::stateless_auth_service::StatelessAuthService;
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use crate::domain::repository::{SessionRepository, UserRepository};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::ops::Add;
use std::sync::Arc;

#[async_trait]
pub trait AuthService: Send + Sync {
    async fn login(
        &self,
        email: String,
        password: String,
    ) -> Result<(TokenPair, UserDTO), AuthError>;
    async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError>;
    async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError>;
    async fn logout(&self, _access_token: String) -> Result<(), AuthError> {
        Err(AuthError::AuthStrategyNotSupported)
    }

    fn generate_token_pair(
        &self,
        user: UserDTO,
        at_duration: i64,
        rt_duration: i64,
        secret: &str,
        session_id: Option<uuid::Uuid>,
    ) -> Result<TokenPair, AuthError> {
        let now = Utc::now();

        let at_exp = now.add(Duration::seconds(at_duration));
        let at_claims = Claims::new(
            at_exp.timestamp() as usize,
            user.clone(),
            TokenType::Access,
            session_id,
        );

        let access_token = encode(
            &Header::default(),
            &at_claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map_err(|_| AuthError::TokenEncodingFailed)?;

        let rt_exp = now.add(Duration::seconds(rt_duration));
        let rt_claims = Claims::new(
            rt_exp.timestamp() as usize,
            user,
            TokenType::Refresh,
            session_id,
        );

        let refresh_token = encode(
            &Header::default(),
            &rt_claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map_err(|_| AuthError::TokenEncodingFailed)?;

        Ok(TokenPair {
            access_token: Token {
                value: access_token,
                expires_at: at_exp.timestamp() as usize,
            },
            refresh_token: Token {
                value: refresh_token,
                expires_at: rt_exp.timestamp() as usize,
            },
        })
    }

    fn validate_token(
        &self,
        token: &str,
        secret: &str,
        expected_type: TokenType,
    ) -> Result<Claims, AuthError> {
        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::InvalidToken,
        })?;

        if decoded.claims.token_type != expected_type {
            return Err(AuthError::InvalidTokenType);
        }

        Ok(decoded.claims)
    }
}

#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    UserNotFound,
    TokenExpired,
    InvalidToken,
    InvalidTokenType,
    InternalError(String),
    TokenEncodingFailed,
    SessionNotFound,
    AuthStrategyNotSupported,
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access_token: Token,
    pub refresh_token: Token,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub value: String,
    pub expires_at: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthStrategy {
    Stateless,
    #[default]
    Stateful,
}

impl AuthStrategy {
    pub fn to_string(&self) -> String {
        match self {
            AuthStrategy::Stateless => "stateless".to_string(),
            AuthStrategy::Stateful => "stateful".to_string(),
        }
    }
}

impl From<AuthStrategy> for String {
    fn from(val: AuthStrategy) -> Self {
        val.to_string()
    }
}

impl TryFrom<String> for AuthStrategy {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "stateless" => Ok(AuthStrategy::Stateless),
            "stateful" => Ok(AuthStrategy::Stateful),
            _ => Err(format!("Unrecognized auth strategy: {}", value)),
        }
    }
}

pub fn create_auth_service(
    config: &AppConfiguration,
    user_repository: Arc<dyn UserRepository>,
    session_repository: Arc<dyn SessionRepository>,
) -> Arc<dyn AuthService> {
    match config.auth_strategy() {
        AuthStrategy::Stateless => Arc::new(StatelessAuthService::new(
            user_repository,
            config.password_hashing_scheme(),
            config.secret().to_string(),
            config.at_duration_in_seconds().to_signed(),
            config.rt_duration_in_seconds().to_signed(),
        )),
        AuthStrategy::Stateful => Arc::new(StatefulAuthService::new(
            user_repository,
            session_repository,
            config.password_hashing_scheme(),
            config.secret().to_string(),
            config.at_duration_in_seconds().to_signed(),
            config.rt_duration_in_seconds().to_signed(),
        )),
    }
}
