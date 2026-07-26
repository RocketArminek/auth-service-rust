use crate::application::service::token_service::{
    Access, Refresh, TokenError, TokenPair, TokenService,
};
use crate::domain::crypto::{Hasher, HashingScheme, SchemeAwareHasher};
use crate::domain::jwt::UserDTO;
use crate::domain::user::PasswordHandler;
use crate::infrastructure::user_repository::UserRepository;

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

impl From<TokenError> for AuthError {
    fn from(error: TokenError) -> Self {
        match error {
            TokenError::Expired => AuthError::TokenExpired,
            TokenError::WrongKind => AuthError::InvalidTokenType,
            TokenError::EncodingFailed => AuthError::TokenEncodingFailed,
            _ => AuthError::InvalidToken,
        }
    }
}

#[derive(Clone)]
pub struct AuthService {
    user_repository: UserRepository,
    hashing_scheme: HashingScheme,
    token_service: TokenService,
}

impl AuthService {
    pub fn new(
        user_repository: UserRepository,
        hashing_scheme: HashingScheme,
        token_service: TokenService,
    ) -> Self {
        Self {
            user_repository,
            hashing_scheme,
            token_service,
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

        Ok((self.token_service.issue_pair(user_dto.clone())?, user_dto))
    }

    pub async fn authenticate(&self, access_token: String) -> Result<UserDTO, AuthError> {
        let claims = self.token_service.validate::<Access>(&access_token)?;

        Ok(claims.into_user())
    }

    pub async fn refresh(&self, refresh_token: String) -> Result<(TokenPair, UserDTO), AuthError> {
        let claims = self.token_service.validate::<Refresh>(&refresh_token)?;
        let user = claims.into_user();

        Ok((self.token_service.issue_pair(user.clone())?, user))
    }

    pub async fn logout(&self, _token: String) -> Result<(), AuthError> {
        Ok(())
    }
}
