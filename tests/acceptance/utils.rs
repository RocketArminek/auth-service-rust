use serde_json::json;
use auth_service::api::dto::LoginResponse;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use crate::utils::context::AcceptanceTestContext;

pub async fn create_admin_with_token(c: &AcceptanceTestContext) -> (User, String) {
    let mut admin = User::now_with_email_and_password(
        String::from("admin@test.com"),
        String::from("Admin#pass1"),
        Some(String::from("Admin")),
        Some(String::from("User")),
        Some(true),
    )
    .unwrap();
    admin.hash_password(&SchemeAwareHasher::default()).unwrap();

    let role = Role::now("ADMIN_USER".to_string()).unwrap();
    c.role_repository.save(&role).await.unwrap();
    admin.add_role(role);
    c.user_repository.save(&admin).await.unwrap();

    let response = c
        .server
        .post("/v1/login")
        .json(&json!({
            "email": "admin@test.com",
            "password": "Admin#pass1",
        }))
        .await;

    let body = response.json::<LoginResponse>();
    (admin, body.access_token.value)
}
