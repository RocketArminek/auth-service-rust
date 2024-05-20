use ::serde_json::json;
use auth_service::domain::user::{PasswordHandler, User};
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use sqlx::{MySql, Pool};
use auth_service::api::dto::{MessageResponse, TokenResponse};
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::role::Role;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use crate::utils::create_test_server;

#[sqlx::test]
async fn it_creates_new_user(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    let email = String::from("jon@snow.test");

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "user",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
}

#[sqlx::test]
async fn it_does_not_create_user_with_invalid_password(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let email = String::from("jon@snow.test");
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "wrong",
            "role": "user",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn it_returns_conflict_if_user_already_exists(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let user =
        User::now_with_email_and_password(email.clone(), String::from("Iknow#othing1")).unwrap();
    repository.add(&user).await.unwrap();
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "user",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CONFLICT);
}

#[sqlx::test]
async fn it_returns_bad_request_if_roles_does_not_exists(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let role = Role::now("user".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    let email = String::from("jon@snow.test");

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "some_role",
        }))
        .await;
    let body = response.json::<MessageResponse>();

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(body.message, "Role does not exist");
}

#[sqlx::test]
async fn it_returns_bad_request_if_role_is_restricted(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let email = String::from("jon@snow.test");

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "ADMIN",
        }))
        .await;
    let body = response.json::<MessageResponse>();

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(body.message, "Role is restricted");
}

#[sqlx::test]
async fn it_returns_bad_request_if_role_is_restricted_2(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let email = String::from("jon@snow.test");

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "admin",
        }))
        .await;
    let body = response.json::<MessageResponse>();

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(body.message, "Role is restricted");
}

#[sqlx::test]
async fn it_returns_bad_request_if_role_restricted_another(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let email = String::from("jon@snow.test");
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();

    let response = server
        .post("/v1/users")
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "ADMIN_USER",
        }))
        .await;
    let body = response.json::<MessageResponse>();

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(body.message, "Role is restricted");
}

#[sqlx::test]
async fn it_creates_restricted_user(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("ned@stark.test"),
        String::from("Iknow#othing1")
    ).unwrap();
    admin.hash_password(&SchemeAwareHasher::default());

    let role_repository = MysqlRoleRepository::new(pool.clone());
    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&admin, role.id).await.unwrap();

    let email = String::from("jon@snow.test");

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "ned@stark.test",
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<TokenResponse>();

    let _response = server
        .post("/v1/restricted/users")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.token)).unwrap(),
        )
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "ADMIN_USER",
        }))
        .await;

    // assert_eq!(response.status_code(), StatusCode::CREATED); TODO
}

#[sqlx::test]
async fn it_cannot_create_restricted_user_if_not_permitted(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone());
    let repository = MysqlUserRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("ned@stark.test"),
        String::from("Iknow#othing1")
    ).unwrap();
    admin.hash_password(&SchemeAwareHasher::default());

    repository.add(&admin).await.unwrap();

    let email = String::from("jon@snow.test");

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "ned@stark.test",
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<TokenResponse>();

    let response = server
        .post("/v1/restricted/users")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.token)).unwrap(),
        )
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "ADMIN_USER",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
}
