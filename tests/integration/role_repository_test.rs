use crate::utils::runners::run_database_test_with_default;
use auth_service::domain::role::Role;
use auth_service::domain::repository::RepositoryError;

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
