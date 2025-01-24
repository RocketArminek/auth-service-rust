use crate::utils::runners::run_database_test_with_default;
use auth_service::domain::repository::RepositoryError;
use auth_service::domain::role::Role;
use auth_service::domain::permission::Permission;
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
        let rows = c.role_repository.get_all(0, 10).await.unwrap();

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
        ).unwrap();

        c.role_repository.save(&role).await.unwrap();
        c.permission_repository.save(&permission).await.unwrap();

        c.role_repository.add_permission(&role.id, &permission.id).await.unwrap();

        let permissions = c.role_repository.get_permissions(&role.id).await.unwrap();
        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0].id, permission.id);

        c.role_repository.remove_permission(&role.id, &permission.id).await.unwrap();

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
        let result = c.role_repository.add_permission(&role.id, &invalid_permission_id).await;

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

        let permission1 = Permission::now(
            "permission1".to_string(),
            "test_group".to_string(),
            None,
        ).unwrap();
        let permission2 = Permission::now(
            "permission2".to_string(),
            "test_group".to_string(),
            None,
        ).unwrap();
        let permission3 = Permission::now(
            "permission3".to_string(),
            "test_group".to_string(),
            None,
        ).unwrap();

        c.permission_repository.save(&permission1).await.unwrap();
        c.permission_repository.save(&permission2).await.unwrap();
        c.permission_repository.save(&permission3).await.unwrap();

        c.role_repository.add_permission(&role1.id, &permission1.id).await.unwrap();
        c.role_repository.add_permission(&role1.id, &permission2.id).await.unwrap();
        c.role_repository.add_permission(&role2.id, &permission2.id).await.unwrap();
        c.role_repository.add_permission(&role2.id, &permission3.id).await.unwrap();

        let permissions = c.role_repository.get_permissions_for_roles(&[role1.id, role2.id]).await.unwrap();
        
        assert_eq!(permissions.len(), 3);
        
        let permission_names: Vec<String> = permissions.iter()
            .map(|p| p.name.clone())
            .collect();
        
        assert!(permission_names.contains(&"permission1".to_string()));
        assert!(permission_names.contains(&"permission2".to_string()));
        assert!(permission_names.contains(&"permission3".to_string()));

        let empty_permissions = c.role_repository.get_permissions_for_roles(&[]).await.unwrap();
        assert!(empty_permissions.is_empty());
    })
    .await;
}
