use crate::utils::runners::run_database_test_with_default;
use auth_service::domain::permission::Permission;
use auth_service::domain::role::Role;
use auth_service::domain::user::User;
use auth_service::infrastructure::repository::RepositoryError;
use std::collections::HashSet;

#[tokio::test]
async fn it_can_add_user() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "jon@snow.test".to_string(),
            "Iknow#othing1".to_string(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();
        let row = c.user_repository.get_by_id(&user.id).await.unwrap();

        assert_eq!(row.email, user.email);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_user_by_email() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "jon@snow.test".to_string(),
            "Iknow#othing1".to_string(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();
        let row = c.user_repository.get_by_email(&user.email).await.unwrap();

        assert_eq!(row.email, user.email);
    })
    .await;
}

#[tokio::test]
async fn it_deletes_user_by_email() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "jon@snow.test".to_string(),
            "Iknow#othing1".to_string(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();
        c.user_repository.save(&user).await.unwrap();
        c.user_repository
            .delete_by_email(&user.email)
            .await
            .unwrap();
        let row = c.user_repository.get_by_email(&user.email).await;

        match row {
            Err(_) => {}
            Ok(user) => panic!("User {} was not deleted", user.email),
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_assign_role_to_user() {
    run_database_test_with_default(|c| async move {
        let mut user = User::now_with_email_and_password(
            "jon@snow.test".to_string(),
            "Iknow#othing1".to_string(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();

        let role = Role::now("admin".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        user.add_role(role.clone());
        c.user_repository.save(&user).await.unwrap();

        let row = c.user_repository.get_by_id(&user.id).await.unwrap();

        assert_eq!(row.roles[0].id, role.id);
        assert_eq!(row.roles[0].name, role.name);
    })
    .await;
}

#[tokio::test]
async fn it_can_update_user_roles() {
    run_database_test_with_default(|c| async move {
        let role1 = Role::now("role1".to_string()).unwrap();
        let role2 = Role::now("role2".to_string()).unwrap();
        let mut user = User::now_with_email_and_password(
            "jon@snow.test".to_string(),
            "Iknow#othing1".to_string(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();

        c.role_repository.save(&role1).await.unwrap();
        user.add_role(role1.clone());
        c.user_repository.save(&user).await.unwrap();

        c.role_repository.save(&role2).await.unwrap();
        user.roles.clear();
        user.add_role(role2.clone());
        c.user_repository.save(&user).await.unwrap();

        let updated_user = c.user_repository.get_by_id(&user.id).await.unwrap();
        assert_eq!(updated_user.roles.len(), 1);
        assert_eq!(updated_user.roles[0].id, role2.id);
        assert_eq!(updated_user.roles[0].name, role2.name);
    })
    .await;
}

#[tokio::test]
async fn it_prevents_save_with_nonexistent_role() {
    run_database_test_with_default(|c| async move {
        let mut user = User::now_with_email_and_password(
            "jon@snow.test".to_string(),
            "Iknow#othing1".to_string(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();

        let non_existent_role = Role::now("nonexistent".to_string()).unwrap();
        user.add_role(non_existent_role);

        let result = c.user_repository.save(&user).await;

        assert!(result.is_err());
        match result {
            Err(RepositoryError::NotFound(msg)) => {
                assert_eq!(msg, "One or more roles not found");
            }
            _ => panic!("Expected NotFound error"),
        }
    })
    .await;
}

#[tokio::test]
async fn it_can_handle_multiple_roles() {
    run_database_test_with_default(|c| async move {
        let role1 = Role::now("role1".to_string()).unwrap();
        let role2 = Role::now("role2".to_string()).unwrap();
        let role3 = Role::now("role3".to_string()).unwrap();
        let mut user = User::now_with_email_and_password(
            "jon@snow.test".to_string(),
            "Iknow#othing1".to_string(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();

        c.role_repository.save(&role1).await.unwrap();
        c.role_repository.save(&role2).await.unwrap();
        c.role_repository.save(&role3).await.unwrap();

        user.add_roles(vec![role1.clone(), role2.clone(), role3.clone()]);
        c.user_repository.save(&user).await.unwrap();

        let saved_user = c.user_repository.get_by_id(&user.id).await.unwrap();
        assert_eq!(saved_user.roles.len(), 3);

        let mut saved_roles: Vec<String> =
            saved_user.roles.iter().map(|r| r.name.clone()).collect();
        saved_roles.sort();
        assert_eq!(saved_roles, vec!["role1", "role2", "role3"]);
    })
    .await;
}

#[tokio::test]
async fn it_can_handle_multiple_roles_removal() {
    run_database_test_with_default(|c| async move {
        let role1 = Role::now("role1".to_string()).unwrap();
        let role2 = Role::now("role2".to_string()).unwrap();
        let role3 = Role::now("role3".to_string()).unwrap();
        let mut user = User::now_with_email_and_password(
            "jon@snow.test".to_string(),
            "Iknow#othing1".to_string(),
            Some(String::from("Jon")),
            Some(String::from("Snow")),
            Some(true),
        )
        .unwrap();

        c.role_repository.save(&role1).await.unwrap();
        c.role_repository.save(&role2).await.unwrap();
        c.role_repository.save(&role3).await.unwrap();

        user.add_roles(vec![role1.clone(), role2.clone(), role3.clone()]);
        c.user_repository.save(&user).await.unwrap();

        user.remove_roles(&[role2]);
        user.remove_role(&role3);
        user.remove_role(&role1);
        c.user_repository.save(&user).await.unwrap();

        let saved_user = c.user_repository.get_by_id(&user.id).await.unwrap();

        assert_eq!(saved_user.roles.len(), 0);
    })
    .await;
}

#[tokio::test]
async fn it_rolls_back_transaction_on_invalid_email() {
    run_database_test_with_default(|c| async move {
        let user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Iknow#othing1".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();

        c.user_repository.save(&user).await.unwrap();

        let user2 = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Iknow#othing1".to_string(),
            Some("Test2".to_string()),
            Some("User2".to_string()),
            Some(true),
        )
        .unwrap();

        let result = c.user_repository.save(&user2).await;
        assert!(result.is_err());

        let saved_user = c.user_repository.get_by_id(&user.id).await.unwrap();
        assert_eq!(saved_user.first_name.unwrap(), "Test");

        let result = c.user_repository.get_by_id(&user2.id).await;
        assert!(result.is_err());
    })
    .await;
}

#[tokio::test]
async fn it_rolls_back_on_invalid_role_without_affecting_user_data() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("valid_role".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let mut user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Iknow#othing1".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();
        user.add_role(role.clone());

        c.user_repository.save(&user).await.unwrap();

        let invalid_role = Role::now("invalid_role".to_string()).unwrap();
        user.roles = vec![invalid_role];

        let result = c.user_repository.save(&user).await;
        assert!(result.is_err());

        let saved_user = c.user_repository.get_by_id(&user.id).await.unwrap();
        assert_eq!(saved_user.roles.len(), 1);
        assert_eq!(saved_user.roles[0].name, "valid_role");
    })
    .await;
}

#[tokio::test]
async fn it_handles_role_updates_atomically() {
    run_database_test_with_default(|c| async move {
        let role1 = Role::now("role1".to_string()).unwrap();
        let role2 = Role::now("role2".to_string()).unwrap();
        let mut user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Test#pass123".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();

        c.role_repository.save(&role1).await.unwrap();
        c.role_repository.save(&role2).await.unwrap();
        user.add_roles(vec![role1.clone(), role2.clone()]);
        c.user_repository.save(&user).await.unwrap();

        let saved_user = c.user_repository.get_by_id(&user.id).await.unwrap();
        assert_eq!(saved_user.roles.len(), 2);

        let invalid_role = Role::now("invalid_role".to_string()).unwrap();
        user.roles = vec![role1.clone(), invalid_role];

        let result = c.user_repository.save(&user).await;
        assert!(result.is_err());

        let user_after_failed_update = c.user_repository.get_by_id(&user.id).await.unwrap();
        assert_eq!(user_after_failed_update.roles.len(), 2);

        let mut role_names: Vec<String> = user_after_failed_update
            .roles
            .iter()
            .map(|r| r.name.clone())
            .collect();
        role_names.sort();

        assert_eq!(role_names, vec!["role1", "role2"]);

        assert_eq!(user_after_failed_update.email, "test@test.com");
        assert_eq!(
            user_after_failed_update.first_name,
            Some("Test".to_string())
        );
        assert_eq!(user_after_failed_update.last_name, Some("User".to_string()));
    })
    .await;
}

#[tokio::test]
async fn it_can_get_user_with_permissions() {
    run_database_test_with_default(|c| async move {
        let role = Role::now("test_role".to_string()).unwrap();
        c.role_repository.save(&role).await.unwrap();

        let permission = Permission::now(
            "test_permission".to_string(),
            "test_group".to_string(),
            Some("Test permission".to_string()),
        )
        .unwrap();
        c.permission_repository.save(&permission).await.unwrap();

        c.role_repository
            .add_permission(&role.id, &permission.id)
            .await
            .unwrap();

        let mut user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Test#pass123".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();
        user.add_role(role);
        c.user_repository.save(&user).await.unwrap();

        let (saved_user, permissions) = c
            .user_repository
            .get_by_id_with_permissions(&user.id)
            .await
            .unwrap();

        assert_eq!(saved_user.id, user.id);
        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0].id, permission.id);
        assert_eq!(permissions[0].name, permission.name);
        assert_eq!(permissions[0].group_name, permission.group_name);
    })
    .await;
}

#[tokio::test]
async fn it_can_get_user_with_overlapping_permissions_from_different_roles() {
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
            "Test#pass123".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();
        user.add_roles(vec![role1.clone(), role2.clone()]);
        c.user_repository.save(&user).await.unwrap();

        let (saved_user, permissions) = c
            .user_repository
            .get_by_id_with_permissions(&user.id)
            .await
            .unwrap();

        assert_eq!(saved_user.id, user.id);
        assert_eq!(permissions.len(), 3);

        let permission_names: Vec<String> = permissions.iter().map(|p| p.name.clone()).collect();
        assert!(permission_names.contains(&"shared_permission".to_string()));
        assert!(permission_names.contains(&"unique_permission1".to_string()));
        assert!(permission_names.contains(&"unique_permission2".to_string()));

        let unique_permission_names: std::collections::HashSet<_> =
            permission_names.iter().collect();
        assert_eq!(permission_names.len(), unique_permission_names.len());
    })
    .await;
}

#[tokio::test]
async fn it_can_get_user_with_permissions_by_email() {
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
            "Test#pass123".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();
        user.add_roles(vec![role1.clone(), role2.clone()]);
        c.user_repository.save(&user).await.unwrap();

        let (saved_user, permissions) = c
            .user_repository
            .get_by_email_with_permissions(&user.email)
            .await
            .unwrap();

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
async fn it_can_get_user_with_complex_overlapping_permissions() {
    run_database_test_with_default(|c| async move {
        let role1 = Role::now("role1".to_string()).unwrap();
        let role2 = Role::now("role2".to_string()).unwrap();
        let role3 = Role::now("role3".to_string()).unwrap();
        c.role_repository.save(&role1).await.unwrap();
        c.role_repository.save(&role2).await.unwrap();
        c.role_repository.save(&role3).await.unwrap();

        let shared_by_all = Permission::now(
            "shared_by_all".to_string(),
            "test_group".to_string(),
            Some("Shared by all roles".to_string()),
        )
        .unwrap();
        let shared_by_1_2 = Permission::now(
            "shared_by_1_2".to_string(),
            "test_group".to_string(),
            Some("Shared by roles 1 and 2".to_string()),
        )
        .unwrap();
        let shared_by_2_3 = Permission::now(
            "shared_by_2_3".to_string(),
            "test_group".to_string(),
            Some("Shared by roles 2 and 3".to_string()),
        )
        .unwrap();
        let unique_to_1 = Permission::now(
            "unique_to_1".to_string(),
            "test_group".to_string(),
            Some("Unique to role 1".to_string()),
        )
        .unwrap();
        let unique_to_3 = Permission::now(
            "unique_to_3".to_string(),
            "test_group".to_string(),
            Some("Unique to role 3".to_string()),
        )
        .unwrap();

        c.permission_repository.save(&shared_by_all).await.unwrap();
        c.permission_repository.save(&shared_by_1_2).await.unwrap();
        c.permission_repository.save(&shared_by_2_3).await.unwrap();
        c.permission_repository.save(&unique_to_1).await.unwrap();
        c.permission_repository.save(&unique_to_3).await.unwrap();

        c.role_repository
            .add_permission(&role1.id, &shared_by_all.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role1.id, &shared_by_1_2.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role1.id, &unique_to_1.id)
            .await
            .unwrap();

        c.role_repository
            .add_permission(&role2.id, &shared_by_all.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role2.id, &shared_by_1_2.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role2.id, &shared_by_2_3.id)
            .await
            .unwrap();

        c.role_repository
            .add_permission(&role3.id, &shared_by_all.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role3.id, &shared_by_2_3.id)
            .await
            .unwrap();
        c.role_repository
            .add_permission(&role3.id, &unique_to_3.id)
            .await
            .unwrap();

        let mut user = User::now_with_email_and_password(
            "test@test.com".to_string(),
            "Test#pass123".to_string(),
            Some("Test".to_string()),
            Some("User".to_string()),
            Some(true),
        )
        .unwrap();
        user.add_roles(vec![role1.clone(), role2.clone(), role3.clone()]);
        c.user_repository.save(&user).await.unwrap();

        let (saved_user, permissions) = c
            .user_repository
            .get_by_id_with_permissions(&user.id)
            .await
            .unwrap();

        assert_eq!(saved_user.id, user.id);
        assert_eq!(permissions.len(), 5);

        let permission_names: Vec<String> = permissions.iter().map(|p| p.name.clone()).collect();

        assert!(permission_names.contains(&"shared_by_all".to_string()));
        assert!(permission_names.contains(&"shared_by_1_2".to_string()));
        assert!(permission_names.contains(&"shared_by_2_3".to_string()));
        assert!(permission_names.contains(&"unique_to_1".to_string()));
        assert!(permission_names.contains(&"unique_to_3".to_string()));

        let unique_permission_names: std::collections::HashSet<_> =
            permission_names.iter().collect();
        assert_eq!(permission_names.len(), unique_permission_names.len());

        let (saved_user_by_email, permissions_by_email) = c
            .user_repository
            .get_by_email_with_permissions(&user.email)
            .await
            .unwrap();

        assert_eq!(saved_user_by_email.id, saved_user.id);
        assert_eq!(permissions_by_email.len(), permissions.len());

        let permission_names_by_email: Vec<String> = permissions_by_email
            .iter()
            .map(|p| p.name.clone())
            .collect();
        assert_eq!(
            permission_names_by_email.iter().collect::<HashSet<_>>(),
            permission_names.iter().collect::<HashSet<_>>()
        );
    })
    .await;
}
