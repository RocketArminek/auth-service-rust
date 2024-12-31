use auth_service::domain::role::Role;
use auth_service::domain::user::User;
use auth_service::infrastructure::mysql_role_repository::{MysqlRoleRepository};
use auth_service::infrastructure::mysql_user_repository::{MysqlUserRepository};
use auth_service::infrastructure::repository::RepositoryError;
use sqlx::{MySql, Pool};
use auth_service::domain::repositories::{RoleRepository, UserRepository};

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_can_add_user(pool: Pool<MySql>) {
    let user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = MysqlUserRepository::new(pool);
    repository.save(&user).await.unwrap();
    let row = repository.get_by_id(user.id).await.unwrap();

    assert_eq!(row.email, user.email);
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_can_get_user_by_email(pool: Pool<MySql>) {
    let user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = MysqlUserRepository::new(pool);
    repository.save(&user).await.unwrap();
    let row = repository.get_by_email(&user.email).await.unwrap();

    assert_eq!(row.email, user.email);
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_deletes_user_by_email(pool: Pool<MySql>) {
    let user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = MysqlUserRepository::new(pool);
    repository.save(&user).await.unwrap();
    repository.delete_by_email(&user.email).await.unwrap();
    let row = repository.get_by_email(&user.email).await;

    match row {
        Err(_) => {}
        Ok(user) => panic!("User {} was not deleted", user.email),
    }
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_can_assign_role_to_user(pool: Pool<MySql>) {
    let mut user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = MysqlUserRepository::new(pool.clone());
    repository.save(&user).await.unwrap();

    let role = Role::now("admin".to_string()).unwrap();
    let role_repository = MysqlRoleRepository::new(pool.clone());
    role_repository.save(&role).await.unwrap();

    user.add_role(role.clone());
    repository.save(&user).await.unwrap();

    let row = repository.get_by_id(user.id).await.unwrap();

    assert_eq!(row.roles[0].id, role.id);
    assert_eq!(row.roles[0].name, role.name);
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_can_be_created_with_role(pool: Pool<MySql>) {
    let role = Role::now("admin".to_string()).unwrap();
    let mut user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    role_repository.save(&role).await.unwrap();
    user.add_role(role.clone());

    repository.save(&user).await.unwrap();

    let row = repository.get_by_email(&user.email).await.unwrap();

    assert_eq!(row.roles[0].id, role.id);
    assert_eq!(row.roles[0].name, role.name);
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_can_update_user_roles(pool: Pool<MySql>) {
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

    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool);

    role_repository.save(&role1).await.unwrap();
    user.add_role(role1.clone());
    repository.save(&user).await.unwrap();

    role_repository.save(&role2).await.unwrap();
    user.roles.clear();
    user.add_role(role2.clone());
    repository.save(&user).await.unwrap();

    let updated_user = repository.get_by_id(user.id).await.unwrap();
    assert_eq!(updated_user.roles.len(), 1);
    assert_eq!(updated_user.roles[0].id, role2.id);
    assert_eq!(updated_user.roles[0].name, role2.name);
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_prevents_save_with_nonexistent_role(pool: Pool<MySql>) {
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

    let repository = MysqlUserRepository::new(pool);
    let result = repository.save(&user).await;

    assert!(result.is_err());
    match result {
        Err(RepositoryError::NotFound(msg)) => {
            assert_eq!(msg, "One or more roles not found");
        }
        _ => panic!("Expected NotFound error"),
    }
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_can_handle_multiple_roles(pool: Pool<MySql>) {
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

    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool);

    role_repository.save(&role1).await.unwrap();
    role_repository.save(&role2).await.unwrap();
    role_repository.save(&role3).await.unwrap();

    user.add_roles(vec![role1.clone(), role2.clone(), role3.clone()]);
    repository.save(&user).await.unwrap();

    let saved_user = repository.get_by_id(user.id).await.unwrap();
    assert_eq!(saved_user.roles.len(), 3);

    let mut saved_roles: Vec<String> = saved_user.roles.iter().map(|r| r.name.clone()).collect();
    saved_roles.sort();
    assert_eq!(saved_roles, vec!["role1", "role2", "role3"]);
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_rolls_back_transaction_on_invalid_email(pool: Pool<MySql>) {
    let repository = MysqlUserRepository::new(pool.clone());

    let user = User::now_with_email_and_password(
        "test@test.com".to_string(),
        "Iknow#othing1".to_string(),
        Some("Test".to_string()),
        Some("User".to_string()),
        Some(true),
    )
    .unwrap();

    repository.save(&user).await.unwrap();

    let user2 = User::now_with_email_and_password(
        "test@test.com".to_string(),
        "Iknow#othing1".to_string(),
        Some("Test2".to_string()),
        Some("User2".to_string()),
        Some(true),
    )
    .unwrap();

    let result = repository.save(&user2).await;
    assert!(result.is_err());

    let saved_user = repository.get_by_id(user.id).await.unwrap();
    assert_eq!(saved_user.first_name.unwrap(), "Test");

    let result = repository.get_by_id(user2.id).await;
    assert!(result.is_err());
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_rolls_back_on_invalid_role_without_affecting_user_data(pool: Pool<MySql>) {
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());

    let role = Role::now("valid_role".to_string()).unwrap();
    role_repository.save(&role).await.unwrap();

    let mut user = User::now_with_email_and_password(
        "test@test.com".to_string(),
        "Iknow#othing1".to_string(),
        Some("Test".to_string()),
        Some("User".to_string()),
        Some(true),
    )
    .unwrap();
    user.add_role(role.clone());

    repository.save(&user).await.unwrap();

    let invalid_role = Role::now("invalid_role".to_string()).unwrap();
    user.roles = vec![invalid_role];

    let result = repository.save(&user).await;
    assert!(result.is_err());

    let saved_user = repository.get_by_id(user.id).await.unwrap();
    assert_eq!(saved_user.roles.len(), 1);
    assert_eq!(saved_user.roles[0].name, "valid_role");
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_maintains_transaction_isolation(pool: Pool<MySql>) {
    let repository = MysqlUserRepository::new(pool.clone());

    let user = User::now_with_email_and_password(
        "test@test.com".to_string(),
        "Iknow#othing1".to_string(),
        Some("Original".to_string()),
        Some("User".to_string()),
        Some(true),
    )
    .unwrap();

    repository.save(&user).await.unwrap();

    let handle1 = tokio::spawn({
        let repository = MysqlUserRepository::new(pool.clone());
        let mut user = user.clone();
        user.first_name = Some("Updated1".to_string());
        async move { repository.save(&user).await }
    });

    let handle2 = tokio::spawn({
        let repository = MysqlUserRepository::new(pool.clone());
        let mut user = user.clone();
        user.first_name = Some("Updated2".to_string());
        async move { repository.save(&user).await }
    });

    let result1 = handle1.await.unwrap();
    let result2 = handle2.await.unwrap();

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    let final_user = repository.get_by_id(user.id).await.unwrap();
    assert!(final_user.first_name.unwrap().starts_with("Updated"));
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_handles_parallel_transactions_with_roles(pool: Pool<MySql>) {
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());

    let role1 = Role::now("role1".to_string()).unwrap();
    let role2 = Role::now("role2".to_string()).unwrap();
    role_repository.save(&role1).await.unwrap();
    role_repository.save(&role2).await.unwrap();

    let mut user = User::now_with_email_and_password(
        "test@test.com".to_string(),
        "Iknow#othing1".to_string(),
        Some("Test".to_string()),
        Some("User".to_string()),
        Some(true),
    )
    .unwrap();
    user.add_role(role1.clone());

    repository.save(&user).await.unwrap();

    let handle1 = tokio::spawn({
        let repository = MysqlUserRepository::new(pool.clone());
        let mut user = user.clone();
        user.roles = vec![role1.clone(), role2.clone()];
        async move { repository.save(&user).await }
    });

    let handle2 = tokio::spawn({
        let repository = MysqlUserRepository::new(pool.clone());
        let mut user = user.clone();
        user.roles = vec![role2.clone()];
        async move { repository.save(&user).await }
    });

    let result1 = handle1.await.unwrap();
    let result2 = handle2.await.unwrap();

    assert!(result1.is_ok());
    assert!(result2.is_ok());

    let final_user = repository.get_by_id(user.id).await.unwrap();
    assert!(final_user.roles.len() > 0);
    assert!(final_user.roles.len() <= 2);
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_handles_concurrent_saves_of_same_user(pool: Pool<MySql>) {
    let user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();

    let repository = MysqlUserRepository::new(pool.clone());

    repository.save(&user).await.unwrap();

    let mut tasks = Vec::new();
    let num_concurrent_operations = 10;

    for i in 0..num_concurrent_operations {
        let repository = MysqlUserRepository::new(pool.clone());
        let mut user = user.clone();
        user.first_name = Some(format!("Jon{}", i));

        let task = tokio::spawn(async move { repository.save(&user).await });
        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }

    for result in results {
        assert!(result.is_ok());
    }

    let final_user = repository.get_by_id(user.id).await.unwrap();
    assert!(final_user.first_name.unwrap().starts_with("Jon"));
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_handles_concurrent_saves_with_role_changes(pool: Pool<MySql>) {
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let roles: Vec<Role> = vec![
        Role::now("role1".to_string()).unwrap(),
        Role::now("role2".to_string()).unwrap(),
        Role::now("role3".to_string()).unwrap(),
        Role::now("role4".to_string()).unwrap(),
        Role::now("role5".to_string()).unwrap(),
    ];

    for role in &roles {
        role_repository.save(role).await.unwrap();
    }

    let mut user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    user.add_role(roles[0].clone());

    let repository = MysqlUserRepository::new(pool.clone());
    repository.save(&user).await.unwrap();

    let mut tasks = Vec::new();
    let num_concurrent_operations = 10;

    for i in 0..num_concurrent_operations {
        let repository = MysqlUserRepository::new(pool.clone());
        let mut user = user.clone();
        user.first_name = Some(format!("Jon{}", i));
        user.roles = vec![roles[i % roles.len()].clone()];

        let task = tokio::spawn(async move { repository.save(&user).await });
        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }

    for result in results {
        assert!(result.is_ok());
    }

    let final_user = repository.get_by_id(user.id).await.unwrap();
    assert!(final_user.first_name.unwrap().starts_with("Jon"));
    assert_eq!(final_user.roles.len(), 1); // Should have exactly one role
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_handles_concurrent_saves_of_different_users(pool: Pool<MySql>) {
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());

    let role = Role::now("shared_role".to_string()).unwrap();
    role_repository.save(&role).await.unwrap();

    let mut users = Vec::new();
    for i in 0..5 {
        let mut user = User::now_with_email_and_password(
            format!("user{}@test.com", i),
            "Iknow#othing1".to_string(),
            Some(format!("User{}", i)),
            Some("Test".to_string()),
            Some(true),
        )
        .unwrap();
        user.add_role(role.clone());
        users.push(user);
    }

    for user in &users {
        repository.save(user).await.unwrap();
    }

    let mut tasks = Vec::new();

    for (i, user) in users.iter().enumerate() {
        let repository = MysqlUserRepository::new(pool.clone());
        let mut user = user.clone();
        user.first_name = Some(format!("UpdatedUser{}", i));

        let task = tokio::spawn(async move { repository.save(&user).await });
        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }

    for result in results {
        assert!(result.is_ok());
    }

    for (i, user) in users.iter().enumerate() {
        let updated_user = repository.get_by_id(user.id).await.unwrap();
        assert_eq!(updated_user.first_name, Some(format!("UpdatedUser{}", i)));
        assert_eq!(updated_user.roles.len(), 1);
        assert_eq!(updated_user.roles[0].id, role.id);
    }
}

#[sqlx::test(migrations = "./migrations/mysql")]
async fn it_handles_rapid_role_changes(pool: Pool<MySql>) {
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());

    let mut roles = Vec::new();
    for i in 0..5 {
        let role = Role::now(format!("role{}", i)).unwrap();
        role_repository.save(&role).await.unwrap();
        roles.push(role);
    }

    let mut user = User::now_with_email_and_password(
        "test@test.com".to_string(),
        "Iknow#othing1".to_string(),
        Some("Test".to_string()),
        Some("User".to_string()),
        Some(true),
    )
    .unwrap();
    user.add_role(roles[0].clone());

    repository.save(&user).await.unwrap();

    let mut tasks = Vec::new();
    let num_concurrent_operations = 20;

    for i in 0..num_concurrent_operations {
        let repository = MysqlUserRepository::new(pool.clone());
        let mut user = user.clone();

        user.roles = vec![
            roles[i % roles.len()].clone(),
            roles[(i + 1) % roles.len()].clone(),
        ];

        let task = tokio::spawn(async move { repository.save(&user).await });
        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }

    for result in results {
        assert!(result.is_ok());
    }

    let final_user = repository.get_by_id(user.id).await.unwrap();
    assert!(final_user.roles.len() > 0); // Should have roles
    assert!(final_user.roles.len() <= 2); // Should have at most 2 roles
}
