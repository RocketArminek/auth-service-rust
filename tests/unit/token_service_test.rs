use auth_service::application::service::keystore::KeyMaterial;
use auth_service::application::service::token_service::{Access, TokenError, TokenService};
use auth_service::domain::jwt::UserDTO;
use auth_service::domain::keystore::{KeyAlgorithm, SigningKey};
use chrono::{Duration, Utc};
use jsonwebtoken::decode_header;
use std::collections::HashMap;
use std::ops::Add;
use uuid::Uuid;

fn test_user() -> UserDTO {
    UserDTO {
        id: Uuid::new_v4(),
        email: "jon@snow.test".to_string(),
        first_name: None,
        last_name: None,
        avatar_path: None,
        roles: vec![],
        permissions: HashMap::new(),
        is_verified: true,
    }
}

fn test_token_service(key: &SigningKey) -> TokenService {
    let key_material = KeyMaterial {
        active: key.clone(),
        verifiers: vec![key.verifying_key()],
    };

    TokenService::new(&key_material, 300, 300, 300, 300).unwrap()
}

#[test]
fn it_signs_tokens_with_kid_in_header() {
    let key = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();
    let token_service = test_token_service(&key);

    let token = token_service.issue::<Access>(test_user()).unwrap();
    let header = decode_header(&token.value).unwrap();

    assert_eq!(header.alg, jsonwebtoken::Algorithm::EdDSA);
    assert_eq!(header.kid, Some(key.kid().to_string()));
}

#[test]
fn it_verifies_tokens_signed_with_active_key() {
    let key = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();
    let token_service = test_token_service(&key);
    let user = test_user();

    let token = token_service.issue::<Access>(user.clone()).unwrap();
    let claims = token_service.validate::<Access>(&token.value).unwrap();

    assert_eq!(claims.user().id, user.id);
}

#[test]
fn it_rejects_token_with_unknown_kid() {
    let key = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();
    let foreign_key = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();

    let token_service = test_token_service(&key);
    let foreign_token_service = test_token_service(&foreign_key);

    let token = foreign_token_service.issue::<Access>(test_user()).unwrap();

    assert_eq!(
        token_service.decode(&token.value).unwrap_err(),
        TokenError::UnknownKid
    );
}

#[test]
fn it_verifies_token_signed_by_retired_key_still_in_verifiers() {
    let retired = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();
    let active = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();

    let old_service = test_token_service(&retired);
    let exp = Utc::now().add(Duration::seconds(300)).timestamp() as usize;
    let old_token = old_service
        .issue_with_exp::<Access>(test_user(), exp)
        .unwrap();

    let key_material = KeyMaterial {
        active: active.clone(),
        verifiers: vec![active.verifying_key(), retired.verifying_key()],
    };
    let token_service = TokenService::new(&key_material, 300, 300, 300, 300).unwrap();

    assert!(token_service.validate::<Access>(&old_token.value).is_ok());

    let new_token = token_service.issue::<Access>(test_user()).unwrap();
    let header = decode_header(&new_token.value).unwrap();

    assert_eq!(header.kid, Some(active.kid().to_string()));
}
