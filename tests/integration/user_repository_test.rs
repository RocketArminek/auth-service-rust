use auth_service::domain::user::User;
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use sqlx::{MySql, Pool, QueryBuilder};
use auth_service::domain::crypto::SchemeAwareHasher;

#[sqlx::test]
async fn it_can_add_user(pool: Pool<MySql>) {
    let user =
        User::now_with_email_and_password("jon@snow.test".to_string(), "Iknow#othing1".to_string())
            .unwrap();
    let repository = MysqlUserRepository::new(pool);
    repository.add(&user).await.unwrap();
    let row = repository.get_by_id(user.id).await.unwrap();

    assert_eq!(row.email, user.email);
}

#[sqlx::test]
async fn it_can_get_user_by_email(pool: Pool<MySql>) {
    let user =
        User::now_with_email_and_password("jon@snow.test".to_string(), "Iknow#othing1".to_string())
            .unwrap();
    let repository = MysqlUserRepository::new(pool);
    repository.add(&user).await.unwrap();
    let row = repository.get_by_email(&user.email).await.unwrap();

    assert_eq!(row.email, user.email);
}

#[sqlx::test]
async fn it_deletes_user_by_email(pool: Pool<MySql>) {
    let user =
        User::now_with_email_and_password("jon@snow.test".to_string(), "Iknow#othing1".to_string())
            .unwrap();
    let repository = MysqlUserRepository::new(pool);
    repository.add(&user).await.unwrap();
    repository.delete_by_email(&user.email).await.unwrap();
    let row = repository.get_by_email(&user.email).await;

    match row {
        None => {}
        Some(user) => panic!("User {} was not deleted", user.email),
    }
}

#[sqlx::test]
async fn it_tests(pool: Pool<MySql>) {
    let mut user =
        User::now_with_email_and_password("jon@snow.test".to_string(), "Iknow#othing1".to_string())
            .unwrap();
    user.hash_password(&SchemeAwareHasher::default());
    let repository = MysqlUserRepository::new(pool.clone());
    repository.add(&user).await.unwrap();

    let mut qb = QueryBuilder::<MySql>::new("SELECT * FROM users WHERE id = ");
    qb.push_bind(&user.id);
    qb.push(" AND email = ");
    qb.push_bind(&user.email);

    let rows = qb.build_query_as::<User>().fetch_all(&pool).await.unwrap();

    for row in rows {
        println!("{:?}", row);
    }
}
