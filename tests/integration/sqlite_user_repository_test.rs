use auth_service::domain::repositories::{RoleRepository, UserRepository};
use auth_service::domain::role::Role;
use auth_service::domain::user::User;
use auth_service::infrastructure::repository::RepositoryError;
use auth_service::infrastructure::sqlite_role_repository::SqliteRoleRepository;
use auth_service::infrastructure::sqlite_user_repository::SqliteUserRepository;
use sqlx::{Pool, Sqlite};

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_can_add_user(pool: Pool<Sqlite>) {
    let user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = SqliteUserRepository::new(pool);
    repository.save(&user).await.unwrap();
    let row = repository.get_by_id(user.id).await.unwrap();

    assert_eq!(row.email, user.email);
}

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_can_get_user_by_email(pool: Pool<Sqlite>) {
    let user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = SqliteUserRepository::new(pool);
    repository.save(&user).await.unwrap();
    let row = repository.get_by_email(&user.email).await.unwrap();

    assert_eq!(row.email, user.email);
}

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_deletes_user_by_email(pool: Pool<Sqlite>) {
    let user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = SqliteUserRepository::new(pool);
    repository.save(&user).await.unwrap();
    repository.delete_by_email(&user.email).await.unwrap();
    let row = repository.get_by_email(&user.email).await;

    match row {
        Err(_) => {}
        Ok(user) => panic!("User {} was not deleted", user.email),
    }
}

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_can_assign_role_to_user(pool: Pool<Sqlite>) {
    let mut user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = SqliteUserRepository::new(pool.clone());
    repository.save(&user).await.unwrap();

    let role = Role::now("admin".to_string()).unwrap();
    let role_repository = SqliteRoleRepository::new(pool.clone());
    role_repository.save(&role).await.unwrap();

    user.add_role(role.clone());
    repository.save(&user).await.unwrap();

    let row = repository.get_by_id(user.id).await.unwrap();

    assert_eq!(row.roles[0].id, role.id);
    assert_eq!(row.roles[0].name, role.name);
}

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_can_be_created_with_role(pool: Pool<Sqlite>) {
    let role = Role::now("admin".to_string()).unwrap();
    let mut user = User::now_with_email_and_password(
        "jon@snow.test".to_string(),
        "Iknow#othing1".to_string(),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let repository = SqliteUserRepository::new(pool.clone());
    let role_repository = SqliteRoleRepository::new(pool.clone());
    role_repository.save(&role).await.unwrap();
    user.add_role(role.clone());

    repository.save(&user).await.unwrap();

    let row = repository.get_by_email(&user.email).await.unwrap();

    assert_eq!(row.roles[0].id, role.id);
    assert_eq!(row.roles[0].name, role.name);
}

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_can_update_user_roles(pool: Pool<Sqlite>) {
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

    let repository = SqliteUserRepository::new(pool.clone());
    let role_repository = SqliteRoleRepository::new(pool);

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

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_prevents_save_with_nonexistent_role(pool: Pool<Sqlite>) {
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

    let repository = SqliteUserRepository::new(pool);
    let result = repository.save(&user).await;

    assert!(result.is_err());
    match result {
        Err(RepositoryError::NotFound(msg)) => {
            assert_eq!(msg, "One or more roles not found");
        }
        _ => panic!("Expected NotFound error"),
    }
}

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_can_handle_multiple_roles(pool: Pool<Sqlite>) {
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

    let repository = SqliteUserRepository::new(pool.clone());
    let role_repository = SqliteRoleRepository::new(pool);

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

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_rolls_back_transaction_on_invalid_email(pool: Pool<Sqlite>) {
    let repository = SqliteUserRepository::new(pool.clone());

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

#[sqlx::test(migrations = "./migrations/sqlite")]
async fn it_rolls_back_on_invalid_role_without_affecting_user_data(pool: Pool<Sqlite>) {
    let repository = SqliteUserRepository::new(pool.clone());
    let role_repository = SqliteRoleRepository::new(pool.clone());

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
