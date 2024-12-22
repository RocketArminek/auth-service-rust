use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use chrono::Utc;
use uuid::Uuid;

#[test]
fn it_can_be_created() {
    let user = User::new(
        Uuid::new_v4(),
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Utc::now(),
        Some(true),
    )
    .unwrap();

    assert_eq!(user.email, String::from("test@test.com"));
    assert_eq!(user.id.is_nil(), false);
}

#[test]
fn it_can_be_created_with_roles() {
    let now = Utc::now();
    let role = Role::now(String::from("USER")).unwrap();
    let user = User::new(
        Uuid::new_v4(),
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        now.clone(),
        Some(true),
    )
    .unwrap()
    .with_roles(vec![role.clone()]);

    assert_eq!(user.id.is_nil(), false);
    assert_eq!(user.email, String::from("test@test.com"));
    assert_eq!(user.first_name, Some(String::from("Jon")));
    assert_eq!(user.last_name, Some(String::from("Snow")));
    assert_eq!(user.created_at, now);
    assert_eq!(user.roles, vec![role])
}

#[test]
fn it_cannot_be_created_with_empty_email() {
    match User::now_with_email_and_password(
        String::from(""),
        String::from("password"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
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
        Some(String::from("Snow")),
        Some(true),
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
        Some(String::from("Snow")),
        Some(true),
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
        Some(String::from("Snow")),
        Some(true),
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
        Some(String::from("Snow")),
        Some(true),
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
        Some(String::from("Snow")),
        Some(true),
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
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let hasher = SchemeAwareHasher::default();
    user.hash_password(&hasher);

    assert_eq!(user.verify_password(&hasher, "Iknow#othing1"), true);
}

#[test]
fn it_has_roles() {
    let mut user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let role = Role::now(String::from("SUPER_ADMIN")).unwrap();

    user.add_role(role);

    assert_eq!(user.roles.len(), 1);
    assert_eq!(user.roles[0].name, String::from("SUPER_ADMIN"));
    assert!(user.has_role(String::from("SUPER_ADMIN")));
}

#[test]
fn it_can_add_multiple_roles() {
    let mut user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let role = Role::now(String::from("SUPER_ADMIN")).unwrap();

    user.add_roles(vec![role]);

    assert_eq!(user.roles.len(), 1);
    assert_eq!(user.roles[0].name, String::from("SUPER_ADMIN"));
    assert!(user.has_role(String::from("SUPER_ADMIN")));
}

#[test]
fn it_does_not_have_roles_by_default() {
    let user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();

    assert_eq!(user.roles.len(), 0);
}

#[test]
fn it_is_not_verified_by_default() {
    let user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        None,
    )
    .unwrap();

    assert_eq!(user.email, String::from("test@test.com"));
    assert_eq!(user.is_verified, false);
}

#[test]
fn it_cannot_add_same_roles_multiple_times() {
    let mut user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    )
    .unwrap();
    let role = Role::now(String::from("SUPER_ADMIN")).unwrap();

    user.add_roles(vec![role.clone(), role.clone()]);

    assert_eq!(user.roles.len(), 1);
    assert_eq!(user.roles[0].name, String::from("SUPER_ADMIN"));
    assert!(user.has_role(String::from("SUPER_ADMIN")));
}
