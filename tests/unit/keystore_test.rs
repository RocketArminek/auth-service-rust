use auth_service::domain::keystore::{
    KeyAlgorithm, KeyEncryptionKey, KeystoreError, SigningKey,
};
use chrono::Utc;

const TEST_KEK: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const OTHER_KEK: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=";

#[test]
fn it_seals_and_unseals_signing_key() {
    let kek = KeyEncryptionKey::from_base64(TEST_KEK).unwrap();
    let key = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();

    let record = key.seal(&kek).unwrap();
    let unsealed = record.unseal(&kek).unwrap();

    assert_eq!(unsealed.kid(), key.kid());
    assert_eq!(unsealed.public_key(), key.public_key());
    assert_eq!(unsealed.private_key_der(), key.private_key_der());
    assert_ne!(record.sealed_private_key, key.private_key_der().to_vec());
}

#[test]
fn it_fails_to_unseal_with_wrong_kek() {
    let kek = KeyEncryptionKey::from_base64(TEST_KEK).unwrap();
    let wrong_kek = KeyEncryptionKey::from_base64(OTHER_KEK).unwrap();
    let key = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();

    let record = key.seal(&kek).unwrap();

    assert!(matches!(
        record.unseal(&wrong_kek),
        Err(KeystoreError::UnsealFailed)
    ));
}

#[test]
fn it_rejects_kek_that_is_not_base64() {
    assert!(matches!(
        KeyEncryptionKey::from_base64("not-valid-base64!!"),
        Err(KeystoreError::InvalidKeyEncryptionKey(_))
    ));
}

#[test]
fn it_rejects_kek_with_wrong_length() {
    assert!(matches!(
        KeyEncryptionKey::from_base64("dG9vc2hvcnQ="),
        Err(KeystoreError::InvalidKeyEncryptionKey(_))
    ));
}

#[test]
fn it_derives_kid_as_rfc7638_thumbprint() {
    let key = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();

    assert_eq!(key.kid().len(), 43);
    assert!(
        key.kid()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    );
}

#[test]
fn it_generates_unique_keys() {
    let first = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();
    let second = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();

    assert_ne!(first.kid(), second.kid());
}

#[test]
fn it_refuses_to_unseal_retired_key() {
    let kek = KeyEncryptionKey::from_base64(TEST_KEK).unwrap();
    let key = SigningKey::generate(KeyAlgorithm::EdDSA).unwrap();

    let mut record = key.seal(&kek).unwrap();
    record.retired_at = Some(Utc::now());

    assert!(matches!(
        record.unseal(&kek),
        Err(KeystoreError::RetiredKeyUnsealed)
    ));
    assert_eq!(record.verifying_key().unwrap().kid, key.kid());
}
