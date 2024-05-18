use sqlx::{MySql, Pool};
use uuid::Uuid;
use auth_service::domain::role::Role;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;

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
async fn it_has_auth_owner_role_by_default(pool: Pool<MySql>) {
    let id = Uuid::parse_str("018f8b15-4759-787c-bc55-1b8337d0e45c").unwrap();

    let repository = MysqlRoleRepository::new(pool);
    let row = repository.get_by_id(id).await.unwrap();

    assert_eq!(row.name, "AUTH_OWNER".to_string());
}

#[sqlx::test]
async fn it_can_get_all_roles(pool: Pool<MySql>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = MysqlRoleRepository::new(pool);
    repository.add(&role).await.unwrap();
    let rows = repository.get_all().await;

    assert_eq!(rows.len(), 2);
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
