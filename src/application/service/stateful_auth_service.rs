use crate::application::service::auth_service::{AuthError, AuthService, TokenPair};
use crate::domain::crypto::{Hasher, HashingScheme, SchemeAwareHasher};
use crate::domain::jwt::{TokenType, UserDTO};
use crate::domain::repository::{SessionRepository, UserRepository};
use crate::domain::session::Session;
use crate::domain::user::PasswordHandler;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct StatefulAuthService {
    user_repository: Arc<dyn UserRepository>,
    session_repository: Arc<dyn SessionRepository>,
    hashing_scheme: HashingScheme,
    secret: String,
    access_token_duration: i64,
    refresh_token_duration: i64,
}

impl StatefulAuthService {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        session_repository: Arc<dyn SessionRepository>,
        hashing_scheme: HashingScheme,
        secret: String,
        access_token_duration: i64,
        refresh_token_duration: i64,
    ) -> Self {
        Self {
            user_repository,
            session_repository,
            hashing_scheme,
            secret,
            access_token_duration,
            refresh_token_duration,
        }
    }

    async fn create_session(
        &self,
        user_id: Uuid,
        session_duration: i64,
    ) -> Result<Session, AuthError> {
        let expires_at = Utc::now() + Duration::seconds(session_duration);
        let session = Session::now(user_id, expires_at);

        self.session_repository
            .save(&session)
            .await
            .map_err(|e| AuthError::InternalError(e.to_string()))?;

        Ok(session)
    }

    async fn validate_session(&self, session_id: &Uuid) -> Result<(Session, UserDTO), AuthError> {
        let (session, user, permissions) = self
            .session_repository
            .get_session_with_user_and_permissions(session_id)
            .await
            .map_err(|_| AuthError::SessionNotFound)?;

        Ok((session, UserDTO::from((user, permissions))))
    }
}

#[async_trait]
impl AuthService for StatefulAuthService {
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

        let session = self
            .create_session(user.id, self.refresh_token_duration)
            .await?;
        let user_dto = UserDTO::from((user, permissions));

        let token_pair = self.generate_token_pair(
            user_dto.clone(),
            self.access_token_duration,
            self.refresh_token_duration,
            &self.secret,
            Some(session.id),
        )?;

        Ok((token_pair, user_dto))
    }

    async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError> {
        let claims = self.validate_token(&access_token, &self.secret, TokenType::Access)?;

        match claims.session_id {
            None => Err(AuthError::InvalidToken),
            Some(session_id) => {
                let (_, user_dto) = self.validate_session(&session_id).await?;
                Ok(user_dto)
            }
        }
    }

    async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError> {
        let claims = self.validate_token(&refresh_token, &self.secret, TokenType::Refresh)?;

        if let Some(session_id) = claims.session_id {
            let (_, user_dto) = self.validate_session(&session_id).await?;

            let r = self.session_repository.delete(&session_id).await;
            match r {
                Ok(_) => {
                    let session = self
                        .create_session(user_dto.id, self.refresh_token_duration)
                        .await?;

                    let token_pair = self.generate_token_pair(
                        user_dto.clone(),
                        self.access_token_duration,
                        self.refresh_token_duration,
                        &self.secret,
                        Some(session.id),
                    )?;

                    Ok((token_pair, user_dto))
                }
                Err(e) => Err(AuthError::InternalError(e.to_string())),
            }
        } else {
            Err(AuthError::InvalidToken)
        }
    }

    async fn logout(&self, access_token: String) -> Result<(), AuthError> {
        let claims = self.validate_token(&access_token, &self.secret, TokenType::Access)?;

        match claims.session_id {
            None => Err(AuthError::InvalidToken),
            Some(session_id) => {
                self.session_repository
                    .delete(&session_id)
                    .await
                    .map_err(|e| AuthError::InternalError(e.to_string()))?;
                Ok(())
            }
        }
    }
}
