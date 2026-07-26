use auth_service::application::service::token_service::{TokenKind, TokenService};
use auth_service::domain::jwt::{Claims, UserDTO};

pub fn decode_claims(token_service: &TokenService, token: &str) -> Claims {
    token_service.decode(token).unwrap()
}

pub fn forge_token<K: TokenKind>(
    token_service: &TokenService,
    user: UserDTO,
    expires_at: usize,
) -> String {
    token_service
        .issue_with_exp::<K>(user, expires_at)
        .unwrap()
        .value
}
