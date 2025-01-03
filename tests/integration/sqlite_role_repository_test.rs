use auth_service::domain::role::Role;
use sqlx::{Pool, Sqlite};
use auth_service::domain::repositories::RoleRepository;
use auth_service::infrastructure::sqlite_role_repository::SqliteRoleRepository;

#[sqlx::test(migrations = "./migrations/sqlite")]
#[cfg(feature = "sqlite")]
async fn it_can_add_role(pool: Pool<Sqlite>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = SqliteRoleRepository::new(pool);
    repository.save(&role).await.unwrap();
    let row = repository.get_by_id(role.id).await.unwrap();

    assert_eq!(row.name, role.name);
}

#[sqlx::test(migrations = "./migrations/sqlite")]
#[cfg(feature = "sqlite")]
async fn it_can_get_role_by_id(pool: Pool<Sqlite>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = SqliteRoleRepository::new(pool);
    repository.save(&role).await.unwrap();
    let row = repository.get_by_id(role.id).await.unwrap();

    assert_eq!(row.name, role.name);
}

#[sqlx::test(migrations = "./migrations/sqlite")]
#[cfg(feature = "sqlite")]
async fn it_can_get_role_by_name(pool: Pool<Sqlite>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = SqliteRoleRepository::new(pool);
    repository.save(&role).await.unwrap();
    let row = repository.get_by_name(&role.name).await.unwrap();

    assert_eq!(row.name, role.name);
}

#[sqlx::test(migrations = "./migrations/sqlite")]
#[cfg(feature = "sqlite")]
async fn it_can_get_all_roles(pool: Pool<Sqlite>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = SqliteRoleRepository::new(pool);
    repository.save(&role).await.unwrap();
    let rows = repository.get_all().await.unwrap();

    assert_eq!(rows.len(), 1);
}

#[sqlx::test(migrations = "./migrations/sqlite")]
#[cfg(feature = "sqlite")]
async fn it_can_delete_role(pool: Pool<Sqlite>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let repository = SqliteRoleRepository::new(pool);
    repository.save(&role).await.unwrap();
    repository.delete(role.id).await.unwrap();
    let row = repository.get_by_id(role.id).await;

    assert!(row.is_err());
    if let Err(e) = row {
        assert!(e.to_string().contains("Entity not found"));
    }
}

#[sqlx::test(migrations = "./migrations/sqlite")]
#[cfg(feature = "sqlite")]
async fn it_name_is_unique(pool: Pool<Sqlite>) {
    let role = Role::now("ROLE".to_string()).unwrap();
    let role2 = Role::now("ROLE".to_string()).unwrap();
    let repository = SqliteRoleRepository::new(pool);
    repository.save(&role).await.unwrap();
    let r = repository.save(&role2).await;

    assert!(r.is_err(), "Should return error");
    if let Err(e) = r {
        assert!(e.to_string().contains("UNIQUE constraint failed: roles.name"));
    }
}

#[sqlx::test(migrations = "./migrations/sqlite")]
#[cfg(feature = "sqlite")]
async fn it_can_update_role(pool: Pool<Sqlite>) {
    let mut role = Role::now("ROLE".to_string()).unwrap();
    let repository = SqliteRoleRepository::new(pool);
    repository.save(&role).await.unwrap();
    role.name = "ROLE2".to_string();
    repository.save(&role).await.unwrap();

    let row = repository.get_by_id(role.id).await.unwrap();

    assert_eq!(row.name, role.name);
}
