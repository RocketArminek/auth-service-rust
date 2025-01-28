use crate::utils::runners::run_database_test_with_default;
use auth_service::domain::permission::Permission;
use auth_service::domain::repository::RepositoryError;
use auth_service::domain::role::Role;
use auth_service::domain::session::Session;
use auth_service::domain::user::User;
use chrono::{Duration, Timelike, Utc};
use std::collections::HashSet;
use uuid::{NoContext, Timestamp, Uuid};

#[tokio::test]
async fn it_can_add_session() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.save(&session).await.unwrap();

        let saved_session = c.session_repository.get_by_id(&session.id).await.unwrap();

        assert_eq!(saved_session.user_id, user.id);
        assert_eq!(saved_session.id, session.id);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_session_by_id() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.save(&session).await.unwrap();

        let saved_session = c.session_repository.get_by_id(&session.id).await.unwrap();

        assert_eq!(saved_session.user_id, user.id);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_sessions_by_user_id() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let session1 = Session::now(user.id, Utc::now() + Duration::hours(1));
        let session2 = Session::now(user.id, Utc::now() + Duration::hours(2));

        c.session_repository.save(&session1).await.unwrap();
        c.session_repository.save(&session2).await.unwrap();

        let sessions = c.session_repository.get_by_user_id(&user.id).await.unwrap();

        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().any(|s| s.id == session1.id));
        assert!(sessions.iter().any(|s| s.id == session2.id));
    })
    .await;
}

#[tokio::test]
async fn it_can_delete_session() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.save(&session).await.unwrap();

        c.session_repository.delete(&session.id).await.unwrap();

        let result = c.session_repository.get_by_id(&session.id).await;

        assert!(result.is_err());
    })
    .await;
}

#[tokio::test]
async fn it_can_delete_all_sessions_by_user_id() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let session1 = Session::now(user.id, Utc::now() + Duration::hours(1));
        let session2 = Session::now(user.id, Utc::now() + Duration::hours(2));

        c.session_repository.save(&session1).await.unwrap();
        c.session_repository.save(&session2).await.unwrap();

        c.session_repository
            .delete_all_by_user_id(&user.id)
            .await
            .unwrap();

        let sessions = c.session_repository.get_by_user_id(&user.id).await.unwrap();

        assert_eq!(sessions.len(), 0);
    })
    .await;
}

#[tokio::test]
async fn it_fails_to_create_session_for_nonexistent_user() {
    run_database_test_with_default(|c| async move {
        let non_existent_user_id = Uuid::new_v4();
        let session = Session::now(non_existent_user_id, Utc::now() + Duration::hours(1));

        let result = c.session_repository.save(&session).await;

        assert!(result.is_err());
    })
    .await;
}

#[tokio::test]
async fn it_can_get_session_with_user() {
    run_database_test_with_default(|c| async move {
        let mut user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        let role = Role::now("AWESOME".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        user.add_role(role);

        c.user_repository.save(&user).await.unwrap();

        let session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.save(&session).await.unwrap();

        let (saved_session, saved_user) = c
            .session_repository
            .get_session_with_user(&session.id)
            .await
            .unwrap();

        assert_eq!(saved_session.id, session.id);
        assert_eq!(saved_session.user_id, user.id);
        assert_eq!(saved_user.id, user.id);
        assert_eq!(saved_user.email, user.email);
        assert_eq!(saved_user.roles.len(), 1);
    })
    .await;
}

#[tokio::test]
async fn it_can_delete_expired_sessions() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let then = Utc::now() - Duration::hours(2);
        let timestamp = Timestamp::from_unix(NoContext, then.timestamp() as u64, then.nanosecond());

        let expired_session = Session::new(
            Uuid::new_v7(timestamp),
            user.id,
            then,
            Utc::now() - Duration::hours(1),
        );
        let valid_session = Session::now(user.id, Utc::now() + Duration::hours(1));

        c.session_repository.save(&expired_session).await.unwrap();
        c.session_repository.save(&valid_session).await.unwrap();

        c.session_repository.delete_expired().await.unwrap();

        let remaining_sessions = c.session_repository.get_by_user_id(&user.id).await.unwrap();
        assert_eq!(remaining_sessions.len(), 1);
        assert_eq!(remaining_sessions[0].id, valid_session.id);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_session_with_user_and_permissions() {
    run_database_test_with_default(|c| async move {
        let role1 = Role::now("role1".to_string()).unwrap();
        let role2 = Role::now("role2".to_string()).unwrap();
        c.role_repository.save(&role1).await.unwrap();
        c.role_repository.save(&role2).await.unwrap();

        let shared_permission = Permission::now(
            "shared_permission".to_string(),
            "test_group".to_string(),
            Some("Shared between roles".to_string()),
        )
        .unwrap();
        let unique_permission1 = Permission::now(
            "unique_permission1".to_string(),
            "test_group".to_string(),
            Some("Unique to role1".to_string()),
        )
        .unwrap();
        let unique_permission2 = Permission::now(
            "unique_permission2".to_string(),
            "test_group".to_string(),
            Some("Unique to role2".to_string()),
        )
        .unwrap();

        c.permission_repository
            .save(&shared_permission)
            .await
            .unwrap();
        c.permission_repository
            .save(&unique_permission1)
            .await
            .unwrap();
        c.permission_repository
            .save(&unique_permission2)
            .await
            .unwrap();

        c.role_repository
            .add_permission(&role1.id, &shared_permission.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role1.id, &unique_permission1.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role2.id, &shared_permission.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role2.id, &unique_permission2.id)
            .await
            .unwrap();

        let mut user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();
        user.add_roles(vec![role1.clone(), role2.clone()]);
        c.user_repository.save(&user).await.unwrap();

        let session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.save(&session).await.unwrap();

        let (saved_session, saved_user, permissions) = c
            .session_repository
            .get_session_with_user_and_permissions(&session.id)
            .await
            .unwrap();

        assert_eq!(saved_session.id, session.id);
        assert_eq!(saved_session.user_id, user.id);
        assert_eq!(saved_user.id, user.id);
        assert_eq!(saved_user.email, user.email);
        assert_eq!(permissions.len(), 3);

        let permission_names: Vec<String> = permissions.iter().map(|p| p.name.clone()).collect();
        assert!(permission_names.contains(&"shared_permission".to_string()));
        assert!(permission_names.contains(&"unique_permission1".to_string()));
        assert!(permission_names.contains(&"unique_permission2".to_string()));

        let unique_permission_names: HashSet<_> = permission_names.iter().collect();
        assert_eq!(permission_names.len(), unique_permission_names.len());
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_for_nonexistent_session_with_user() {
    run_database_test_with_default(|c| async move {
        let non_existent_id = Uuid::new_v4();
        let result = c
            .session_repository
            .get_session_with_user(&non_existent_id)
            .await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(msg)) => {
                assert_eq!(
                    msg,
                    format!("Session not found with id: {}", non_existent_id)
                );
            }
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_update_existing_session() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Password123!".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();

        let mut session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.save(&session).await.unwrap();

        let new_expiry = Utc::now() + Duration::hours(2);
        session.expires_at = new_expiry;

        c.session_repository.save(&session).await.unwrap();

        let updated_session = c.session_repository.get_by_id(&session.id).await.unwrap();

        assert_eq!(updated_session.id, session.id);
        assert_eq!(updated_session.user_id, user.id);
        assert!(
            (updated_session.expires_at - new_expiry)
                .num_milliseconds()
                .abs()
                < 1000,
            "Expiry time should be within 1 second tolerance"
        );
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_when_getting_nonexistent_session_with_user() {
    run_database_test_with_default(|c| async move {
        let non_existent_id = Uuid::new_v4();
        let result = c
            .session_repository
            .get_session_with_user(&non_existent_id)
            .await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(msg)) => {
                assert_eq!(
                    msg,
                    format!("Session not found with id: {}", non_existent_id)
                );
            }
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_when_getting_nonexistent_session_with_user_and_permissions() {
    run_database_test_with_default(|c| async move {
        let non_existent_id = Uuid::new_v4();
        let result = c
            .session_repository
            .get_session_with_user_and_permissions(&non_existent_id)
            .await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(msg)) => {
                assert_eq!(
                    msg,
                    format!("Session not found with id: {}", non_existent_id)
                );
            }
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}
