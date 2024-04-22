use sqlx::{Pool, MySql};
use auth_service::domain::user::User;
use auth_service::infrastructure::sqlx_user_repository::MysqlUserRepository;

#[sqlx::test]
async fn it_can_add_user(pool: Pool<MySql>) {
    let user = User::now_with_email_and_password("jon@snow.test".to_string(), "iknownothing".to_string()).unwrap();
    let repository = MysqlUserRepository::new(pool);
    repository.add(&user).await.unwrap();
    let row = repository.get_by_id(user.id).await.unwrap();

    assert_eq!(row.email, user.email);
}

#[sqlx::test]
async fn it_can_get_user_by_email(pool: Pool<MySql>) {
    let user = User::now_with_email_and_password("jon@snow.test".to_string(), "iknownothing".to_string()).unwrap();
    let repository = MysqlUserRepository::new(pool);
    repository.add(&user).await.unwrap();
    let row = repository.get_by_email(&user.email).await.unwrap();

    assert_eq!(row.email, user.email);
}
