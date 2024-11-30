use auth_service::domain::role::Role;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use sqlx::{MySql, Pool};

#[sqlx::test]
async fn it_can_add_role(pool: Pool<MySql>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = MysqlRoleRepository::new(pool);
    repository.add(&role).await.unwrap();
    let row = repository.get_by_id(role.id).await.unwrap();

    assert_eq!(row.name, role.name);
}

#[sqlx::test]
async fn it_can_get_role_by_id(pool: Pool<MySql>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = MysqlRoleRepository::new(pool);
    repository.add(&role).await.unwrap();
    let row = repository.get_by_id(role.id).await.unwrap();

    assert_eq!(row.name, role.name);
}

#[sqlx::test]
async fn it_can_get_role_by_name(pool: Pool<MySql>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = MysqlRoleRepository::new(pool);
    repository.add(&role).await.unwrap();
    let row = repository.get_by_name(&role.name).await.unwrap();

    assert_eq!(row.name, role.name);
}

#[sqlx::test]
async fn it_can_get_all_roles(pool: Pool<MySql>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = MysqlRoleRepository::new(pool);
    repository.add(&role).await.unwrap();
    let rows = repository.get_all().await;

    assert_eq!(rows.len(), 1);
}

#[sqlx::test]
async fn it_can_delete_role(pool: Pool<MySql>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = MysqlRoleRepository::new(pool);
    repository.add(&role).await.unwrap();
    repository.delete(role.id).await.unwrap();
    let row = repository.get_by_id(role.id).await;

    assert!(row.is_none());
}
