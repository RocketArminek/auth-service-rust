use std::ops::Add;
use std::sync::Arc;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use crate::application::auth_service::{AuthError, AuthService, Token, TokenPair};
use crate::domain::crypto::{Hasher, HashingScheme, SchemeAwareHasher};
use crate::domain::jwt::{Claims, TokenType, UserDTO};
use crate::domain::repositories::UserRepository;
use crate::domain::user::PasswordHandler;

#[derive(Clone)]
pub struct StatelessAuthService {
    user_repository: Arc<dyn UserRepository>,
    hashing_scheme: HashingScheme,
    secret: String,
    access_token_duration: i64,
    refresh_token_duration: i64,
}

impl StatelessAuthService {
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

    fn generate_token_pair(&self, user: UserDTO) -> Result<TokenPair, AuthError> {
        let now = Utc::now();

        let at_exp = now.add(Duration::seconds(self.access_token_duration));
        let at_claims = Claims::new(
            at_exp.timestamp() as usize,
            user.clone(),
            TokenType::Access,
        );

        let access_token = encode(
            &Header::default(),
            &at_claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        ).map_err(|_| AuthError::TokenEncodingFailed)?;

        let rt_exp = now.add(Duration::seconds(self.refresh_token_duration));
        let rt_claims = Claims::new(
            rt_exp.timestamp() as usize,
            user,
            TokenType::Refresh,
        );

        let refresh_token = encode(
            &Header::default(),
            &rt_claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        ).map_err(|_| AuthError::TokenEncodingFailed)?;

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

    fn validate_token(&self, token: &str, expected_type: TokenType) -> Result<UserDTO, AuthError> {
        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        ).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::InvalidToken,
        })?;

        if decoded.claims.token_type != expected_type {
            return Err(AuthError::InvalidTokenType);
        }

        Ok(decoded.claims.user)
    }
}

#[async_trait]
impl AuthService for StatelessAuthService {
    async fn login(&self, email: String, password: String)
        -> Result<(TokenPair, UserDTO), AuthError>
    {
        let user = self.user_repository
            .get_by_email(&email)
            .await
            .map_err(|_| AuthError::UserNotFound)?;

        let hasher = SchemeAwareHasher::with_scheme(self.hashing_scheme);

        if !user.verify_password(&hasher, &password) {
            return Err(AuthError::InvalidCredentials);
        }

        if hasher.is_password_outdated(&user.password) {
            let mut outdated_user = user.clone();
            let scheme = self.hashing_scheme;
            let user_repository = self.user_repository.clone();
            tokio::task::spawn(async move {
                tracing::debug!(
                        "Password hash outdated for {}({}), updating...",
                        &outdated_user.email,
                        &outdated_user.id
                    );
                let new_password = SchemeAwareHasher::with_scheme(scheme)
                    .hash_password(&password)
                    .unwrap_or(outdated_user.password.clone());
                outdated_user.set_password(new_password);
                let outdated_user = outdated_user.into();
                match user_repository.save(&outdated_user).await {
                    Ok(_) => tracing::debug!(
                            "Password updated for {}({})",
                            &outdated_user.email,
                            &outdated_user.id
                        ),
                    Err(e) => tracing::error!("Could not update password hash {:?}", e),
                }
            });
        }

        let user_dto = UserDTO::from(user);
        Ok((self.generate_token_pair(user_dto.clone())?, user_dto))
    }

    async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError> {
        self.validate_token(&access_token, TokenType::Access)
    }

    async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError> {
        let user_dto = self.validate_token(&refresh_token, TokenType::Refresh)?;

        Ok((self.generate_token_pair(user_dto.clone())?, user_dto))
    }
}
