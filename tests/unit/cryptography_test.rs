use auth_service::domain::crypto::{
    Argon2Hasher, BcryptHasher, Hasher, HashingScheme, SchemeAwareHasher,
};

#[test]
fn it_can_hash_password_using_argon2() {
    let argon_hasher = Argon2Hasher::new();
    let hash = argon_hasher.hash_password("password").unwrap();
    let is_ok = argon_hasher.verify_password("password", &hash);

    assert!(is_ok);
}

#[test]
fn it_can_hash_password_using_bcrypt() {
    let bcrypt_hasher = BcryptHasher::default();
    let hash = bcrypt_hasher.hash_password("password").unwrap();
    let is_ok = bcrypt_hasher.verify_password("password", &hash);

    assert!(is_ok);
}

#[test]
fn it_can_hash_based_on_password_scheme() {
    let scheme_aware_hasher = SchemeAwareHasher::default();
    let hash = scheme_aware_hasher.hash_password("password").unwrap();
    let is_ok = scheme_aware_hasher.verify_password("password", &hash);
    let mut expected_scheme = scheme_aware_hasher.current_scheme.to_string();
    expected_scheme.push('.');
    let contains_scheme = hash.contains(&expected_scheme);

    assert!(is_ok);
    assert!(contains_scheme);
}

#[test]
fn it_can_verify_password_using_previous_scheme() {
    let scheme_01 = SchemeAwareHasher::with_scheme(HashingScheme::Argon2);
    let scheme_02 = SchemeAwareHasher::with_scheme(HashingScheme::Bcrypt);

    let hash = scheme_01.hash_password("password").unwrap();
    let is_ok = scheme_02.verify_password("password", &hash);

    assert!(is_ok);
}

#[test]
fn it_can_check_if_hash_needs_rehash() {
    let scheme_01 = SchemeAwareHasher::with_scheme(HashingScheme::Argon2);
    let scheme_02 = SchemeAwareHasher::with_scheme(HashingScheme::Bcrypt);

    let hash = scheme_01.hash_password("password").unwrap();
    let needs_rehash_01 = scheme_01.is_password_outdated(&hash);
    let needs_rehash_02 = scheme_02.is_password_outdated(&hash);

    assert!(!needs_rehash_01);
    assert!(needs_rehash_02);
}

#[test]
fn it_can_create_low_cost_bcrypt() {
    let bcrypt_hasher = BcryptHasher::low_cost();
    let hash = bcrypt_hasher.hash_password("password").unwrap();
    let is_ok = bcrypt_hasher.verify_password("password", &hash);

    assert!(is_ok);
}
