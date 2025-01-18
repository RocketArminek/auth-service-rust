use crate::application::auth_service::{AuthError, AuthService, TokenPair};
use crate::domain::crypto::{Hasher, HashingScheme, SchemeAwareHasher};
use crate::domain::jwt::{TokenType, UserDTO};
use crate::domain::repositories::UserRepository;
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
        let user = self
            .user_repository
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

        Ok((
            self.generate_token_pair(
                user_dto.clone(),
                self.access_token_duration,
                self.refresh_token_duration,
                &self.secret
            )?,
            user_dto
        ))
    }

    async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError> {
        self.validate_token(&access_token, &self.secret, TokenType::Access)
    }

    async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError> {
        let user_dto = self.validate_token(
            &refresh_token,
            &self.secret,
            TokenType::Refresh
        )?;

        Ok((
            self.generate_token_pair(
                user_dto.clone(),
                self.access_token_duration,
                self.refresh_token_duration,
                &self.secret
            )?,
            user_dto
        ))
    }
}
