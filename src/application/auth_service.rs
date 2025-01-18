use std::ops::Add;
use crate::application::app_configuration::AppConfiguration;
use crate::application::stateless_auth_service::StatelessAuthService;
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use crate::domain::repositories::UserRepository;
use async_trait::async_trait;
use std::sync::Arc;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

#[async_trait]
pub trait AuthService: Send + Sync {
    async fn login(
        &self,
        email: String,
        password: String,
    ) -> Result<(TokenPair, UserDTO), AuthError>;
    async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError>;
    async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError>;

    fn generate_token_pair(
        &self,
        user: UserDTO,
        at_duration: i64,
        rt_duration: i64,
        secret: &str
    ) -> Result<TokenPair, AuthError> {
        let now = Utc::now();

        let at_exp = now.add(Duration::seconds(at_duration));
        let at_claims = Claims::new(at_exp.timestamp() as usize, user.clone(), TokenType::Access);

        let access_token = encode(
            &Header::default(),
            &at_claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
            .map_err(|_| AuthError::TokenEncodingFailed)?;

        let rt_exp = now.add(Duration::seconds(rt_duration));
        let rt_claims = Claims::new(rt_exp.timestamp() as usize, user, TokenType::Refresh);

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
        expected_type: TokenType
    ) -> Result<UserDTO, AuthError> {
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

        Ok(decoded.claims.user)
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

#[derive(Debug, Clone)]
pub enum AuthStrategy {
    Stateless,
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

impl Into<String> for AuthStrategy {
    fn into(self) -> String {
        self.to_string()
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

impl Default for AuthStrategy {
    fn default() -> Self {
        AuthStrategy::Stateless
    }
}

pub fn create_auth_service(
    config: &AppConfiguration,
    user_repository: Arc<dyn UserRepository>,
) -> Arc<dyn AuthService> {
    match config.auth_strategy() {
        AuthStrategy::Stateless => Arc::new(StatelessAuthService::new(
            user_repository,
            config.password_hashing_scheme(),
            config.secret().to_string(),
            config.at_duration_in_seconds().to_signed(),
            config.rt_duration_in_seconds().to_signed(),
        )),
        AuthStrategy::Stateful => panic!("Unsupported auth strategy"),
    }
}
