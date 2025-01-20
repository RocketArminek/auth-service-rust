use crate::utils::context::AcceptanceTestContext;
use auth_service::api::dto::LoginResponse;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use serde_json::json;

pub async fn i_am_logged_in_as_admin(c: &AcceptanceTestContext) -> (User, String) {
    create_and_login(c, "admin@test.com", "Admin#pass1", Some("ADMIN_USER")).await
}

pub async fn i_am_logged_in_as_user(c: &AcceptanceTestContext) -> (User, String) {
    create_and_login(c, "user@test.com", "User#pass1", None).await
}

async fn create_and_login(c: &AcceptanceTestContext, email: &str, password: &str, role: Option<&str>) -> (User, String) {
    let role = role.map(|r| Role::now(r.to_string()).unwrap());

    let mut user = User::now_with_email_and_password(
        email.to_string(),
        password.to_string(),
        Some(String::from("User")),
        Some(String::from("Regular")),
        Some(true),
    ).unwrap();
    user.hash_password(&SchemeAwareHasher::default()).unwrap();

    match role {
        None => {}
        Some(role) => {
            c.role_repository.save(&role).await.unwrap();
            user.add_role(role);
        }
    }

    c.user_repository.save(&user).await.unwrap();

    let response = c
        .server
        .post("/v1/login")
        .json(&json!({
            "email": email.to_string(),
            "password": password.to_string(),
        }))
        .await;

    let body = response.json::<LoginResponse>();
    (user, body.access_token.value)
}
