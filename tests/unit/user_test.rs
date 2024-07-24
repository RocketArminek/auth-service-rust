use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::user::{PasswordHandler, User};
use chrono::{Utc};
use uuid::Uuid;
use auth_service::domain::role::Role;

#[test]
fn it_can_be_created() {
    let user = User::new(
        Uuid::new_v4(),
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Utc::now(),
    ).unwrap();

    assert_eq!(user.email, String::from("test@test.com"));
    assert_eq!(user.id.is_nil(), false);
}

#[test]
fn it_cannot_be_created_with_empty_email() {
    match User::now_with_email_and_password(
        String::from(""),
        String::from("password"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_cannot_be_created_with_empty_password() {
    match User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from(""),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_cannot_be_created_with_invalid_email() {
    match User::now_with_email_and_password(
        String::from("invalid-email"),
        String::from("password"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_cannot_be_created_without_special_character() {
    match User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Password1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_cannot_be_created_without_uppercase_character() {
    match User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("password1#"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_cannot_be_created_without_lowercase_character() {
    match User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("PASSWORD1#"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_can_verify_password_using_hasher() {
    let mut user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    )
    .unwrap();
    let hasher = SchemeAwareHasher::default();
    user.hash_password(&hasher);

    assert_eq!(user.verify_password(&hasher, "Iknow#othing1"), true);
}

#[test]
fn user_has_roles() {
    let mut user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();
    let role = Role::now(String::from("SUPER_ADMIN")).unwrap();

    user.add_role(role);

    assert_eq!(user.roles.len(), 1);
    assert_eq!(user.roles[0].name, String::from("SUPER_ADMIN"));
    assert!(user.has_role(String::from("SUPER_ADMIN")));
}

#[test]
fn user_does_not_have_roles_by_default() {
    let user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow"))
    ).unwrap();

    assert_eq!(user.roles.len(), 0);
}
