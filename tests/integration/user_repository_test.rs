use crate::utils::runners::run_database_test_with_default;
use auth_service::domain::role::Role;
use auth_service::domain::user::User;
use auth_service::domain::repository::RepositoryError;

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
