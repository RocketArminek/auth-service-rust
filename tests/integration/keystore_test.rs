use crate::utils::runners::run_database_test_with_default;
use auth_service::application::service::keystore::{KeystoreInitError, initialize_keystore};
use auth_service::domain::keystore::{KeyAlgorithm, KeyEncryptionKey, KeystoreError};

const TEST_KEK: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const OTHER_KEK: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=";

#[tokio::test]
async fn it_generates_key_on_empty_store() {
    run_database_test_with_default(|c| async move {
        let kek = KeyEncryptionKey::from_base64(TEST_KEK).unwrap();

        let key_material =
            initialize_keystore(&c.signing_key_repository, &kek, KeyAlgorithm::EdDSA)
                .await
                .unwrap();

        let records = c.signing_key_repository.find_all().await.unwrap();

        assert_eq!(records.len(), 1);
        assert!(records[0].is_active());
        assert_eq!(records[0].kid, key_material.active.kid());
        assert_eq!(key_material.verifiers.len(), 1);
    })
    .await;
}

#[tokio::test]
async fn it_reuses_existing_active_key() {
    run_database_test_with_default(|c| async move {
        let kek = KeyEncryptionKey::from_base64(TEST_KEK).unwrap();

        let first = initialize_keystore(&c.signing_key_repository, &kek, KeyAlgorithm::EdDSA)
            .await
            .unwrap();
        let second = initialize_keystore(&c.signing_key_repository, &kek, KeyAlgorithm::EdDSA)
            .await
            .unwrap();

        assert_eq!(first.active.kid(), second.active.kid());
        assert_eq!(
            c.signing_key_repository.find_all().await.unwrap().len(),
            1
        );
    })
    .await;
}

#[tokio::test]
async fn it_converges_on_one_key_when_instances_boot_concurrently() {
    run_database_test_with_default(|c| async move {
        let kek = KeyEncryptionKey::from_base64(TEST_KEK).unwrap();

        let (first, second) = tokio::join!(
            initialize_keystore(&c.signing_key_repository, &kek, KeyAlgorithm::EdDSA),
            initialize_keystore(&c.signing_key_repository, &kek, KeyAlgorithm::EdDSA),
        );

        let first = first.unwrap();
        let second = second.unwrap();

        assert_eq!(first.active.kid(), second.active.kid());
        assert_eq!(
            c.signing_key_repository.find_all().await.unwrap().len(),
            1
        );
    })
    .await;
}

#[tokio::test]
async fn it_fails_on_first_key_access_with_wrong_kek() {
    run_database_test_with_default(|c| async move {
        let kek = KeyEncryptionKey::from_base64(TEST_KEK).unwrap();
        let wrong_kek = KeyEncryptionKey::from_base64(OTHER_KEK).unwrap();

        initialize_keystore(&c.signing_key_repository, &kek, KeyAlgorithm::EdDSA)
            .await
            .unwrap();

        let result =
            initialize_keystore(&c.signing_key_repository, &wrong_kek, KeyAlgorithm::EdDSA).await;

        assert!(matches!(
            result,
            Err(KeystoreInitError::Keystore(KeystoreError::UnsealFailed))
        ));
    })
    .await;
}
