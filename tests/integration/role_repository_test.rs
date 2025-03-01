use crate::utils::runners::run_database_test_with_default;
use auth_service::domain::permission::Permission;
use auth_service::domain::repository::RepositoryError;
use auth_service::domain::role::Role;
use uuid::Uuid;

#[tokio::test]
async fn it_can_add_role() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        let row = c.role_repository.get_by_id(&role.id).await.unwrap();

        assert_eq!(row.name, role.name);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_role_by_id() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        let row = c.role_repository.get_by_id(&role.id).await.unwrap();

        assert_eq!(row.name, role.name);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_role_by_name() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        let row = c.role_repository.get_by_name(&role.name).await.unwrap();

        assert_eq!(row.name, role.name);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_all_roles() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        let rows = c.role_repository.get_all(1, 10).await.unwrap();

        assert_eq!(rows.len(), 1);
    })
    .await;
}

#[tokio::test]
async fn it_can_delete_role() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        c.role_repository.delete(&role.id).await.unwrap();

        let row = c.role_repository.get_by_id(&role.id).await;

        assert!(row.is_err());
        if let Err(e) = row {
            assert!(e.to_string().contains("Entity not found"));
        }
    })
    .await;
}

#[tokio::test]
async fn it_name_is_unique() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("ROLE".to_string()).unwrap();
        let role2 = Role::now("ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        let r = c.role_repository.save(&role2).await;

        assert!(r.is_err(), "Should return error");
        match r {
            Ok(_) => panic!("Should not return Ok"),
            Err(RepositoryError::Database(_)) => {}
            _ => panic!("Should return conflict error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_update_role() {
    run_database_test_with_default(|c| async move {
        let mut role = Role::now("ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        role.name = "ROLE2".to_string();
        c.role_repository.save(&role).await.unwrap();

        let row = c.role_repository.get_by_id(&role.id).await.unwrap();

        assert_eq!(row.name, role.name);
    })
    .await;
}

#[tokio::test]
async fn it_can_mark_role_as_system() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        c.role_repository.mark_as_system(&role.id).await.unwrap();

        let result = c.role_repository.delete(&role.id).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Cannot delete system role"));
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_manage_role_permissions() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        let permission = Permission::now(
            "test_permission".to_string(),
            "test_group".to_string(),
            None,
        )
        .unwrap();

        c.role_repository.save(&role).await.unwrap();
        c.permission_repository.save(&permission).await.unwrap();

        c.role_repository
            .add_permission(&role.id, &permission.id)
            .await
            .unwrap();

        let permissions = c.role_repository.get_permissions(&role.id).await.unwrap();
        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0].id, permission.id);

        c.role_repository
            .remove_permission(&role.id, &permission.id)
            .await
            .unwrap();

        let permissions = c.role_repository.get_permissions(&role.id).await.unwrap();
        assert_eq!(permissions.len(), 0);
    })
    .await;
}

#[tokio::test]
async fn it_handles_invalid_permission_assignments() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let invalid_permission_id = Uuid::new_v4();
        let result = c
            .role_repository
            .add_permission(&role.id, &invalid_permission_id)
            .await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(msg)) => {
                assert_eq!(msg, "Permission not found");
            }
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_get_permissions_for_multiple_roles() {
    run_database_test_with_default(|c| async move {
        let role1 = Role::now("ROLE_1".to_string()).unwrap();
        let role2 = Role::now("ROLE_2".to_string()).unwrap();
        c.role_repository.save(&role1).await.unwrap();
        c.role_repository.save(&role2).await.unwrap();

        let permission1 =
            Permission::now("permission1".to_string(), "test_group".to_string(), None).unwrap();
        let permission2 =
            Permission::now("permission2".to_string(), "test_group".to_string(), None).unwrap();
        let permission3 =
            Permission::now("permission3".to_string(), "test_group".to_string(), None).unwrap();

        c.permission_repository.save(&permission1).await.unwrap();
        c.permission_repository.save(&permission2).await.unwrap();
        c.permission_repository.save(&permission3).await.unwrap();

        c.role_repository
            .add_permission(&role1.id, &permission1.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role1.id, &permission2.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role2.id, &permission2.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role2.id, &permission3.id)
            .await
            .unwrap();

        let permissions = c
            .role_repository
            .get_permissions_for_roles(&[role1.id, role2.id])
            .await
            .unwrap();

        assert_eq!(permissions.len(), 3);

        let permission_names: Vec<String> = permissions.iter().map(|p| p.name.clone()).collect();

        assert!(permission_names.contains(&"permission1".to_string()));
        assert!(permission_names.contains(&"permission2".to_string()));
        assert!(permission_names.contains(&"permission3".to_string()));

        let empty_permissions = c
            .role_repository
            .get_permissions_for_roles(&[])
            .await
            .unwrap();
        assert!(empty_permissions.is_empty());
    })
    .await;
}

#[tokio::test]
async fn it_can_get_role_with_permissions() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        let permission1 = Permission::now(
            "permission1".to_string(),
            "test_group".to_string(),
            Some("Test permission 1".to_string()),
        )
        .unwrap();
        let permission2 = Permission::now(
            "permission2".to_string(),
            "test_group".to_string(),
            Some("Test permission 2".to_string()),
        )
        .unwrap();

        c.role_repository.save(&role).await.unwrap();
        c.permission_repository.save(&permission1).await.unwrap();
        c.permission_repository.save(&permission2).await.unwrap();

        c.role_repository
            .add_permission(&role.id, &permission1.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role.id, &permission2.id)
            .await
            .unwrap();

        let (fetched_role, permissions) = c
            .role_repository
            .get_by_id_with_permissions(&role.id)
            .await
            .unwrap();

        assert_eq!(fetched_role.id, role.id);
        assert_eq!(fetched_role.name, role.name);
        assert_eq!(permissions.len(), 2);

        let permission_names: Vec<String> = permissions.iter().map(|p| p.name.clone()).collect();
        assert!(permission_names.contains(&"permission1".to_string()));
        assert!(permission_names.contains(&"permission2".to_string()));
    })
    .await;
}

#[tokio::test]
async fn it_can_get_role_without_permissions() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let (fetched_role, permissions) = c
            .role_repository
            .get_by_id_with_permissions(&role.id)
            .await
            .unwrap();

        assert_eq!(fetched_role.id, role.id);
        assert_eq!(fetched_role.name, role.name);
        assert_eq!(permissions.len(), 0);
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_for_nonexistent_role_with_permissions() {
    run_database_test_with_default(|c| async move {
        let result = c
            .role_repository
            .get_by_id_with_permissions(&Uuid::new_v4())
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
async fn it_can_get_role_by_name_with_permissions() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        let permission1 = Permission::now(
            "permission1".to_string(),
            "test_group".to_string(),
            Some("Test permission 1".to_string()),
        )
        .unwrap();
        let permission2 = Permission::now(
            "permission2".to_string(),
            "test_group".to_string(),
            Some("Test permission 2".to_string()),
        )
        .unwrap();

        c.role_repository.save(&role).await.unwrap();
        c.permission_repository.save(&permission1).await.unwrap();
        c.permission_repository.save(&permission2).await.unwrap();

        c.role_repository
            .add_permission(&role.id, &permission1.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role.id, &permission2.id)
            .await
            .unwrap();

        let (fetched_role, permissions) = c
            .role_repository
            .get_by_name_with_permissions(&role.name)
            .await
            .unwrap();

        assert_eq!(fetched_role.id, role.id);
        assert_eq!(fetched_role.name, role.name);
        assert_eq!(permissions.len(), 2);

        let permission_names: Vec<String> = permissions.iter().map(|p| p.name.clone()).collect();
        assert!(permission_names.contains(&"permission1".to_string()));
        assert!(permission_names.contains(&"permission2".to_string()));
    })
    .await;
}

#[tokio::test]
async fn it_can_get_role_by_name_without_permissions() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let (fetched_role, permissions) = c
            .role_repository
            .get_by_name_with_permissions(&role.name)
            .await
            .unwrap();

        assert_eq!(fetched_role.id, role.id);
        assert_eq!(fetched_role.name, role.name);
        assert_eq!(permissions.len(), 0);
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_for_nonexistent_role_name_with_permissions() {
    run_database_test_with_default(|c| async move {
        let result = c
            .role_repository
            .get_by_name_with_permissions("NONEXISTENT_ROLE")
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
async fn it_can_get_all_roles_with_permissions() {
    run_database_test_with_default(|c| async move {
        let role1 = Role::now("ROLE_1".to_string()).unwrap();
        let role2 = Role::now("ROLE_2".to_string()).unwrap();
        c.role_repository.save(&role1).await.unwrap();
        c.role_repository.save(&role2).await.unwrap();

        let permission1 = Permission::now(
            "permission1".to_string(),
            "test_group".to_string(),
            Some("Test permission 1".to_string()),
        )
        .unwrap();
        let permission2 = Permission::now(
            "permission2".to_string(),
            "test_group".to_string(),
            Some("Test permission 2".to_string()),
        )
        .unwrap();

        c.permission_repository.save(&permission1).await.unwrap();
        c.permission_repository.save(&permission2).await.unwrap();

        c.role_repository
            .add_permission(&role1.id, &permission1.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role1.id, &permission2.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role2.id, &permission2.id)
            .await
            .unwrap();

        let roles_with_permissions = c
            .role_repository
            .get_all_with_permissions(1, 10)
            .await
            .unwrap();

        assert_eq!(roles_with_permissions.len(), 2);

        let role1_result = roles_with_permissions
            .iter()
            .find(|(r, _)| r.id == role1.id)
            .unwrap();
        let role2_result = roles_with_permissions
            .iter()
            .find(|(r, _)| r.id == role2.id)
            .unwrap();

        assert_eq!(role1_result.1.len(), 2);
        assert_eq!(role2_result.1.len(), 1);

        let role1_permission_names: Vec<String> =
            role1_result.1.iter().map(|p| p.name.clone()).collect();
        assert!(role1_permission_names.contains(&"permission1".to_string()));
        assert!(role1_permission_names.contains(&"permission2".to_string()));

        let role2_permission_names: Vec<String> =
            role2_result.1.iter().map(|p| p.name.clone()).collect();
        assert!(role2_permission_names.contains(&"permission2".to_string()));
    })
    .await;
}

#[tokio::test]
async fn it_can_paginate_roles_with_permissions() {
    run_database_test_with_default(|c| async move {
        for i in 1..=5 {
            let role = Role::now(format!("ROLE_{}", i)).unwrap();
            c.role_repository.save(&role).await.unwrap();

            let permission =
                Permission::now(format!("permission_{}", i), "test_group".to_string(), None)
                    .unwrap();
            c.permission_repository.save(&permission).await.unwrap();
            c.role_repository
                .add_permission(&role.id, &permission.id)
                .await
                .unwrap();
        }

        let page1 = c
            .role_repository
            .get_all_with_permissions(1, 2)
            .await
            .unwrap();
        let page2 = c
            .role_repository
            .get_all_with_permissions(2, 2)
            .await
            .unwrap();
        let page3 = c
            .role_repository
            .get_all_with_permissions(3, 2)
            .await
            .unwrap();

        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page3.len(), 1);

        for (role, permissions) in page1.iter().chain(page2.iter()).chain(page3.iter()) {
            assert_eq!(permissions.len(), 1);
            let role_number = role.name.split('_').last().unwrap();
            let permission = &permissions[0];
            assert_eq!(permission.name, format!("permission_{}", role_number));
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_delete_role_by_name() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        c.role_repository.delete_by_name(&role.name).await.unwrap();

        let result = c.role_repository.get_by_name(&role.name).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Entity not found"));
        }
    })
    .await;
}

#[tokio::test]
async fn it_cannot_delete_system_role_by_name() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("TEST_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        c.role_repository.mark_as_system(&role.id).await.unwrap();

        let result = c.role_repository.delete_by_name(&role.name).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Cannot delete system role"));
        }
    })
    .await;
}

#[tokio::test]
async fn it_returns_not_found_when_deleting_nonexistent_role_by_name() {
    run_database_test_with_default(|c| async move {
        let result = c.role_repository.delete_by_name("NONEXISTENT_ROLE").await;
        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(_)) => {}
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_prevents_modifying_system_role_permissions() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("SYSTEM_ROLE".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();
        c.role_repository.mark_as_system(&role.id).await.unwrap();

        let permission =
            Permission::now("TEST_PERM".to_string(), "test".to_string(), None).unwrap();
        c.permission_repository.save(&permission).await.unwrap();

        let add_result = c
            .role_repository
            .add_permission(&role.id, &permission.id)
            .await;
        assert!(add_result.is_err());
        assert!(
            add_result
                .unwrap_err()
                .to_string()
                .contains("Cannot modify permissions")
        );

        let remove_result = c
            .role_repository
            .remove_permission(&role.id, &permission.id)
            .await;
        assert!(remove_result.is_err());
        assert!(
            remove_result
                .unwrap_err()
                .to_string()
                .contains("Cannot modify permissions")
        );
    })
    .await;
}
