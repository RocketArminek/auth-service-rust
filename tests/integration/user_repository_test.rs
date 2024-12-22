use auth_service::domain::role::Role;
use auth_service::domain::user::User;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use sqlx::{MySql, Pool};

#[sqlx::test]
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

#[sqlx::test]
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

#[sqlx::test]
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

#[sqlx::test]
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
    role_repository.add(&role).await.unwrap();

    user.add_role(role.clone());
    repository.save(&user).await.unwrap();

    let row = repository.get_by_id(user.id).await.unwrap();

    assert_eq!(row.roles[0].id, role.id);
    assert_eq!(row.roles[0].name, role.name);
}

#[sqlx::test]
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
    role_repository.add(&role).await.unwrap();
    user.add_role(role.clone());

    repository.save(&user).await.unwrap();

    let row = repository.get_by_email(&user.email).await.unwrap();

    assert_eq!(row.roles[0].id, role.id);
    assert_eq!(row.roles[0].name, role.name);
}

#[sqlx::test]
async fn it_cannot_be_created_with_not_existing_role(pool: Pool<MySql>) {
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
    user.add_role(role);
    let result = repository.save(&user).await;

    assert!(result.is_err());

    let row = repository.get_by_email(&user.email).await;
    assert!(row.is_err());
}
