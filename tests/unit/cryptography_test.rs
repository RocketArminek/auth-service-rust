use auth_service::domain::cryptography::{Argon2Hasher, Hasher};

#[test]
fn it_can_hash_password() {
    let argon_hasher = Argon2Hasher::new();
    let hash = argon_hasher.hash_password("password").unwrap();
    let is_ok = argon_hasher.verify_password("password", &hash);

    assert_eq!(is_ok, true);
}
