use crate::utils::runners::run_database_test_with_default;
use auth_service::domain::session::Session;
use auth_service::domain::user::User;
use chrono::{Duration, Utc};
use uuid::Uuid;

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
        c.user_repository.lock().await.save(&user).await.unwrap();

        let session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.lock().await.save(&session).await.unwrap();

        let saved_session = c
            .session_repository
            .lock()
            .await
            .get_by_id(&session.id)
            .await
            .unwrap();

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
        c.user_repository.lock().await.save(&user).await.unwrap();

        let session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.lock().await.save(&session).await.unwrap();

        let saved_session = c
            .session_repository
            .lock()
            .await
            .get_by_id(&session.id)
            .await
            .unwrap();

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
        c.user_repository.lock().await.save(&user).await.unwrap();

        let session1 = Session::now(user.id, Utc::now() + Duration::hours(1));
        let session2 = Session::now(user.id, Utc::now() + Duration::hours(2));

        c.session_repository.lock().await.save(&session1).await.unwrap();
        c.session_repository.lock().await.save(&session2).await.unwrap();

        let sessions = c
            .session_repository
            .lock()
            .await
            .get_by_user_id(&user.id)
            .await
            .unwrap();

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
        c.user_repository.lock().await.save(&user).await.unwrap();

        let session = Session::now(user.id, Utc::now() + Duration::hours(1));
        c.session_repository.lock().await.save(&session).await.unwrap();

        c.session_repository
            .lock()
            .await
            .delete(&session.id)
            .await
            .unwrap();

        let result = c
            .session_repository
            .lock()
            .await
            .get_by_id(&session.id)
            .await;

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
        c.user_repository.lock().await.save(&user).await.unwrap();

        let session1 = Session::now(user.id, Utc::now() + Duration::hours(1));
        let session2 = Session::now(user.id, Utc::now() + Duration::hours(2));

        c.session_repository.lock().await.save(&session1).await.unwrap();
        c.session_repository.lock().await.save(&session2).await.unwrap();

        c.session_repository
            .lock()
            .await
            .delete_all_by_user_id(&user.id)
            .await
            .unwrap();

        let sessions = c
            .session_repository
            .lock()
            .await
            .get_by_user_id(&user.id)
            .await
            .unwrap();

        assert_eq!(sessions.len(), 0);
    })
    .await;
}

#[tokio::test]
async fn it_fails_to_create_session_for_nonexistent_user() {
    run_database_test_with_default(|c| async move {
        let non_existent_user_id = Uuid::new_v4();
        let session = Session::now(non_existent_user_id, Utc::now() + Duration::hours(1));
        
        let result = c.session_repository.lock().await.save(&session).await;
        
        assert!(result.is_err());
    })
    .await;
}
