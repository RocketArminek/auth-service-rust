use auth_service::application::service::token_service::{TokenKind, TokenService};
use auth_service::domain::jwt::{Claims, UserDTO};

pub fn test_token_service(secret: &str) -> TokenService {
    TokenService::new(secret.to_string(), 300, 300, 300, 300)
}

pub fn decode_claims(secret: &str, token: &str) -> Claims {
    test_token_service(secret).decode(token).unwrap()
}

pub fn forge_token<K: TokenKind>(secret: &str, user: UserDTO, expires_at: usize) -> String {
    test_token_service(secret)
        .issue_with_exp::<K>(user, expires_at)
        .unwrap()
        .value
}
