use ::serde_json::json;
use auth_service::domain::user::{PasswordHandler, User};
use auth_service::infrastructure::mysql_user_repository::MysqlUserRepository;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use sqlx::{MySql, Pool};
use uuid::Uuid;
use auth_service::api::dto::{LoginResponse, MessageResponse, UserListResponse};
use auth_service::domain::crypto::{HashingScheme, SchemeAwareHasher};
use auth_service::domain::jwt::UserDTO;
use auth_service::domain::role::Role;
use auth_service::infrastructure::mysql_role_repository::MysqlRoleRepository;
use crate::utils::create_test_server;

#[sqlx::test]
async fn it_creates_new_user(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
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
            "first_name": "Jon",
            "last_name": "Snow",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
}

#[sqlx::test]
async fn it_does_not_create_user_with_invalid_password(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
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
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let email = String::from("jon@snow.test");
    let user =
        User::now_with_email_and_password(
            email.clone(),
            String::from("Iknow#othing1"),
            Some(String::from("Jon")),
            Some(String::from("Snow"))
        ).unwrap();
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
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
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
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
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
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
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
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
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
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("ned@stark.test"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
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
    let body = response.json::<LoginResponse>();

    let response = server
        .post("/v1/restricted/users")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "ADMIN_USER",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
}

#[sqlx::test]
async fn it_cannot_create_restricted_user_if_not_permitted(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("ned@stark.test"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
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
    let body = response.json::<LoginResponse>();

    let response = server
        .post("/v1/restricted/users")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .json(&json!({
            "email": &email,
            "password": "Iknow#othing1",
            "role": "ADMIN_USER",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn it_can_list_all_user_as_an_privileged_role(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("ned@stark.test"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    admin.hash_password(&SchemeAwareHasher::default());

    let role_repository = MysqlRoleRepository::new(pool.clone());
    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&admin, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "ned@stark.test",
            "password": "Iknow#othing1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .get("/v1/restricted/users?page=1&limit=10")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body = response.json::<UserListResponse>();

    assert_eq!(body.items.len(), 1);
    assert_eq!(body.items[0].email, "ned@stark.test");
    assert_eq!(body.limit, 10);
    assert_eq!(body.page, 1);
    assert_eq!(body.total, 1);
    assert_eq!(body.pages, 1);
}

#[sqlx::test]
async fn it_can_get_single_user(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("admin@test.com"),
        String::from("Admin#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    admin.hash_password(&SchemeAwareHasher::default());

    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&admin, role.id).await.unwrap();

    let user = User::now_with_email_and_password(
        String::from("user@test.com"),
        String::from("User#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "admin@test.com",
            "password": "Admin#pass1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .get(&format!("/v1/restricted/users/{}", user.id))
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body = response.json::<UserDTO>();
    assert_eq!(body.email, "user@test.com");
}

#[sqlx::test]
async fn it_can_delete_user(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("admin@test.com"),
        String::from("Admin#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    admin.hash_password(&SchemeAwareHasher::default());

    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&admin, role.id).await.unwrap();

    let user = User::now_with_email_and_password(
        String::from("user@test.com"),
        String::from("User#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "admin@test.com",
            "password": "Admin#pass1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .delete(&format!("/v1/restricted/users/{}", user.id))
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let deleted_user = repository.get_by_id(user.id).await;
    assert!(deleted_user.is_none());
}

#[sqlx::test]
async fn it_returns_not_found_for_nonexistent_user(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("admin@test.com"),
        String::from("Admin#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    admin.hash_password(&SchemeAwareHasher::default());

    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&admin, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "admin@test.com",
            "password": "Admin#pass1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let non_existent_id = Uuid::new_v4();
    let response = server
        .get(&format!("/v1/restricted/users/{}", non_existent_id))
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn it_updates_user_information(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());

    let mut user = User::now_with_email_and_password(
        String::from("user@test.com"),
        String::from("User#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    user.hash_password(&SchemeAwareHasher::default());

    let role = Role::now("USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&user, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "user@test.com",
            "password": "User#pass1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .put("/v1/me")
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .json(&json!({
            "firstName": "Jon",
            "lastName": "Doe",
            "avatarPath": "https://somepath.com/123.jpg"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body = response.json::<UserDTO>();
    assert_eq!(body.first_name.unwrap(), "Jon");
    assert_eq!(body.last_name.unwrap(), "Doe");
    assert_eq!(body.avatar_path.unwrap(), "https://somepath.com/123.jpg");
}

#[sqlx::test]
async fn it_updates_other_user_information(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, None, 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("admin@test.com"),
        String::from("Admin#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    admin.hash_password(&SchemeAwareHasher::default());

    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&admin, role.id).await.unwrap();

    let user = User::now_with_email_and_password(
        String::from("user@test.com"),
        String::from("User#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    repository.add(&user).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "admin@test.com",
            "password": "Admin#pass1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .put(&format!("/v1/restricted/users/{}", user.id))
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .json(&json!({
            "firstName": "Jon",
            "lastName": "Doe",
            "avatarPath": "https://somepath.com/123.jpg",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let body = response.json::<UserDTO>();
    assert_eq!(body.first_name.unwrap(), "Jon");
    assert_eq!(body.last_name.unwrap(), "Doe");
    assert_eq!(body.avatar_path.unwrap(), "https://somepath.com/123.jpg");
}

#[sqlx::test]
async fn it_cannot_update_none_existing_user(pool: Pool<MySql>) {
    let server = create_test_server("secret".to_string(), pool.clone(), HashingScheme::BcryptLow, Some("ADMIN".to_string()), 60, 60, true);
    let repository = MysqlUserRepository::new(pool.clone());
    let role_repository = MysqlRoleRepository::new(pool.clone());
    let mut admin = User::now_with_email_and_password(
        String::from("admin@test.com"),
        String::from("Admin#pass1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    admin.hash_password(&SchemeAwareHasher::default());

    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    role_repository.add(&role).await.unwrap();
    repository.add_with_role(&admin, role.id).await.unwrap();

    let response = server
        .post("/v1/stateless/login")
        .json(&json!({
            "email": "admin@test.com",
            "password": "Admin#pass1",
        }))
        .await;
    let body = response.json::<LoginResponse>();

    let response = server
        .put(&format!("/v1/restricted/users/{}", Uuid::new_v4()))
        .add_header(
            HeaderName::try_from("Authorization").unwrap(),
            HeaderValue::try_from(format!("Bearer {}", body.access_token.value)).unwrap(),
        )
        .json(&json!({
            "email": "test@wp.pl",
            "firstName": "Jon",
            "lastName": "Doe",
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}
