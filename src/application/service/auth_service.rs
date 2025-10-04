use crate::domain::crypto::{Hasher, HashingScheme, SchemeAwareHasher};
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use crate::domain::repository::UserRepository;
use crate::domain::user::PasswordHandler;
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::ops::Add;
use std::sync::Arc;

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

#[derive(Clone)]
pub struct AuthService {
    user_repository: Arc<dyn UserRepository>,
    hashing_scheme: HashingScheme,
    secret: String,
    access_token_duration: i64,
    refresh_token_duration: i64,
}

impl AuthService {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        hashing_scheme: HashingScheme,
        secret: String,
        access_token_duration: i64,
        refresh_token_duration: i64,
    ) -> Self {
        Self {
            user_repository,
            hashing_scheme,
            secret,
            access_token_duration,
            refresh_token_duration,
        }
    }

    pub async fn login(
        &self,
        email: String,
        password: String,
    ) -> Result<(TokenPair, UserDTO), AuthError> {
        let (mut user, permissions) = self
            .user_repository
            .get_by_email_with_permissions(&email)
            .await
            .map_err(|_| AuthError::UserNotFound)?;

        if !user.verify_password(
            &SchemeAwareHasher::with_scheme(self.hashing_scheme),
            &password,
        ) {
            return Err(AuthError::InvalidCredentials);
        }

        if SchemeAwareHasher::with_scheme(self.hashing_scheme).is_password_outdated(&user.password)
        {
            let new_password =
                SchemeAwareHasher::with_scheme(self.hashing_scheme).hash_password(&password);
            match new_password {
                Ok(new_password) => {
                    user.set_password(new_password);
                    match self.user_repository.save(&user).await {
                        Ok(_) => {
                            tracing::debug!("Password updated for {}({})", &user.email, &user.id)
                        }
                        Err(e) => tracing::error!("Could not update password hash {:?}", e),
                    }
                }
                Err(e) => tracing::error!("Could not update password hash {:?}", e),
            }
        }

        let user_dto = UserDTO::from((user, permissions));

        Ok((
            self.generate_token_pair(
                user_dto.clone(),
                self.access_token_duration,
                self.refresh_token_duration,
                &self.secret,
                None,
            )?,
            user_dto,
        ))
    }

    pub async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError> {
        let claims = self.validate_token(&access_token, &self.secret, TokenType::Access)?;

        Ok(claims.user)
    }

    pub async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError> {
        let claims = self.validate_token(&refresh_token, &self.secret, TokenType::Refresh)?;

        Ok((
            self.generate_token_pair(
                claims.user.clone(),
                self.access_token_duration,
                self.refresh_token_duration,
                &self.secret,
                None,
            )?,
            claims.user,
        ))
    }

    pub async fn logout(&self, _token: String) -> Result<(), AuthError> {
        Ok(())
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
