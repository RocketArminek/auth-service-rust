use crate::utils::runners::run_database_test_with_default;
use auth_service::domain::permission::Permission;
use auth_service::domain::repository::RepositoryError;
use uuid::Uuid;

#[tokio::test]
async fn it_can_add_permission() {
    run_database_test_with_default(|c| async move {
        let permission = Permission::now(
            "create_user".to_string(),
            "user_management".to_string(),
            Some("Allows creating new users".to_string()),
        )
        .unwrap();

        c.permission_repository.save(&permission).await.unwrap();
        let saved = c
            .permission_repository
            .get_by_id(&permission.id)
            .await
            .unwrap();

        assert_eq!(saved.name, permission.name);
        assert_eq!(saved.group_name, permission.group_name);
        assert_eq!(saved.description, permission.description);
        assert_eq!(saved.is_system, permission.is_system);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_permission_by_id() {
    run_database_test_with_default(|c| async move {
        let permission = Permission::now(
            "delete_user".to_string(),
            "user_management".to_string(),
            Some("Allows deleting users".to_string()),
        )
        .unwrap();

        c.permission_repository.save(&permission).await.unwrap();
        let saved = c
            .permission_repository
            .get_by_id(&permission.id)
            .await
            .unwrap();

        assert_eq!(saved.id, permission.id);
        assert_eq!(saved.name, permission.name);
        assert_eq!(saved.group_name, permission.group_name);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_permission_by_name_and_group() {
    run_database_test_with_default(|c| async move {
        let permission = Permission::now(
            "edit_user".to_string(),
            "user_management".to_string(),
            Some("Allows editing users".to_string()),
        )
        .unwrap();

        c.permission_repository.save(&permission).await.unwrap();
        let saved = c
            .permission_repository
            .get_by_name(&permission.name, &permission.group_name)
            .await
            .unwrap();

        assert_eq!(saved.id, permission.id);
        assert_eq!(saved.name, permission.name);
        assert_eq!(saved.group_name, permission.group_name);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_all_permissions() {
    run_database_test_with_default(|c| async move {
        let permission1 = Permission::now(
            "create_role".to_string(),
            "role_management".to_string(),
            None,
        )
        .unwrap();

        let permission2 = Permission::now(
            "delete_role".to_string(),
            "role_management".to_string(),
            None,
        )
        .unwrap();

        c.permission_repository.save(&permission1).await.unwrap();
        c.permission_repository.save(&permission2).await.unwrap();

        let permissions = c.permission_repository.get_all(0, 10).await.unwrap();

        assert_eq!(permissions.len(), 2);
        assert!(permissions.iter().any(|p| p.id == permission1.id));
        assert!(permissions.iter().any(|p| p.id == permission2.id));
    })
    .await;
}

#[tokio::test]
async fn it_enforces_unique_name_and_group_combination() {
    run_database_test_with_default(|c| async move {
        let permission1 = Permission::now(
            "manage_users".to_string(),
            "user_management".to_string(),
            None,
        )
        .unwrap();

        let permission2 = Permission::now(
            "manage_users".to_string(),
            "user_management".to_string(),
            None,
        )
        .unwrap();

        c.permission_repository.save(&permission1).await.unwrap();
        let result = c.permission_repository.save(&permission2).await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::Database(_)) => {}
            _ => panic!("Expected database error for unique constraint violation"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_paginate_permissions() {
    run_database_test_with_default(|c| async move {
        for i in 1..=5 {
            let permission =
                Permission::now(format!("permission_{}", i), "test_group".to_string(), None)
                    .unwrap();
            c.permission_repository.save(&permission).await.unwrap();
        }

        let page1 = c.permission_repository.get_all(0, 2).await.unwrap();
        let page2 = c.permission_repository.get_all(2, 2).await.unwrap();
        let page3 = c.permission_repository.get_all(4, 2).await.unwrap();

        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page3.len(), 1);
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_for_nonexistent_permission() {
    run_database_test_with_default(|c| async move {
        let result = c.permission_repository.get_by_id(&Uuid::new_v4()).await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_return_not_found_for_nonexistent_permission_by_name_and_group() {
    run_database_test_with_default(|c| async move {
        let result = c
            .permission_repository
            .get_by_name("nonexistent", "nonexistent")
            .await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_update_permission() {
    run_database_test_with_default(|c| async move {
        let mut permission = Permission::now(
            "update_user".to_string(),
            "user_management".to_string(),
            Some("Allows updating users".to_string()),
        )
        .unwrap();
        c.permission_repository.save(&permission).await.unwrap();

        permission.description = Some("Allows updating user information".to_string());
        c.permission_repository.save(&permission).await.unwrap();

        let updated = c
            .permission_repository
            .get_by_id(&permission.id)
            .await
            .unwrap();

        assert_eq!(updated.description, permission.description);
    })
    .await;
}

#[tokio::test]
async fn it_can_mark_permission_as_system() {
    run_database_test_with_default(|c| async move {
        let permission = Permission::now(
            "system_permission".to_string(),
            "system".to_string(),
            Some("A system permission".to_string()),
        )
        .unwrap();

        c.permission_repository.save(&permission).await.unwrap();
        c.permission_repository
            .mark_as_system(&permission.id)
            .await
            .unwrap();

        let result = c.permission_repository.delete(&permission.id).await;
        assert!(result.is_err());
        match result {
            Err(RepositoryError::Conflict(msg)) => {
                assert_eq!(msg, "Cannot delete system permission");
            }
            _ => panic!("Expected Conflict error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_delete_permission() {
    run_database_test_with_default(|c| async move {
        let permission = Permission::now(
            "deletable_permission".to_string(),
            "test_group".to_string(),
            None,
        )
        .unwrap();

        c.permission_repository.save(&permission).await.unwrap();
        c.permission_repository
            .delete(&permission.id)
            .await
            .unwrap();

        let result = c.permission_repository.get_by_id(&permission.id).await;
        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_cannot_mark_nonexistent_permission_as_system() {
    run_database_test_with_default(|c| async move {
        let nonexistent_id = Uuid::new_v4();
        let result = c
            .permission_repository
            .mark_as_system(&nonexistent_id)
            .await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(msg)) => {
                assert!(msg.contains("Permission with id"));
            }
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_cannot_delete_nonexistent_permission() {
    run_database_test_with_default(|c| async move {
        let nonexistent_id = Uuid::new_v4();
        let result = c.permission_repository.delete(&nonexistent_id).await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}
