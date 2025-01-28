use crate::application::service::auth_service::{AuthError, AuthService, TokenPair};
use crate::domain::crypto::{Hasher, HashingScheme, SchemeAwareHasher};
use crate::domain::jwt::{TokenType, UserDTO};
use crate::domain::repository::UserRepository;
use crate::domain::user::PasswordHandler;
use async_trait::async_trait;
use std::sync::Arc;

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
}

#[async_trait]
impl AuthService for StatelessAuthService {
    async fn login(
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

    async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError> {
        let claims = self.validate_token(&access_token, &self.secret, TokenType::Access)?;

        Ok(claims.user)
    }

    async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError> {
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
}
