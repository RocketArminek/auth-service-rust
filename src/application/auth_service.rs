use std::sync::Arc;
use async_trait::async_trait;
use crate::application::app_configuration::AppConfiguration;
use crate::application::stateless_auth_service::StatelessAuthService;
use crate::domain::jwt::UserDTO;
use crate::domain::repositories::UserRepository;

#[async_trait]
pub trait AuthService: Send + Sync {
    /// Authenticates user with email and password
    /// Returns TokenPair containing access and refresh tokens if successful
    ///
    /// # Errors
    /// - InvalidCredentials if password doesn't match
    /// - UserNotFound if email doesn't exist
    /// - InternalError for other failures
    async fn login(&self, email: String, password: String) -> Result<(TokenPair, UserDTO), AuthError>;

    /// Validates access token and returns user information
    /// Used for protecting routes and getting current user context
    ///
    /// # Errors
    /// - InvalidToken for malformed tokens
    /// - TokenExpired for expired tokens
    /// - InvalidTokenType if not an access token
    async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError>;

    /// Uses refresh token to generate new token pair
    ///
    /// # Errors
    /// - InvalidToken for malformed tokens
    /// - TokenExpired for expired tokens
    /// - InvalidTokenType if not a refresh token
    async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError>;
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
    Stateful
}

impl AuthStrategy {
    pub fn to_string(&self) -> String {
        match self {
            AuthStrategy::Stateless => "stateless".to_string(),
            AuthStrategy::Stateful => "stateful".to_string()
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
            _ => Err(format!("Unrecognized auth strategy: {}", value))
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
        AuthStrategy::Stateless => {
            Arc::new(
                StatelessAuthService::new(
                    user_repository,
                    config.password_hashing_scheme(),
                    config.secret().to_string(),
                    config.at_duration_in_seconds().to_signed(),
                    config.rt_duration_in_seconds().to_signed(),
                )
            )
        }
        AuthStrategy::Stateful => panic!("Unsupported auth strategy"),
    }
}
