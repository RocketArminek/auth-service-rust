use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::user::User;
use chrono::{Utc};
use uuid::Uuid;

#[test]
fn it_can_be_created() {
    let user = User::new(
        Uuid::new_v4(),
        String::from("test@test.com"),
        String::from("Iknow#othing1"),
        Utc::now(),
    ).unwrap();

    assert_eq!(user.email, String::from("test@test.com"));
    assert_eq!(user.id.is_nil(), false);
}

#[test]
fn it_cannot_be_created_with_empty_email() {
    match User::now_with_email_and_password(String::from(""), String::from("password")) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_cannot_be_created_with_empty_password() {
    match User::now_with_email_and_password(String::from("test@test.com"), String::from("")) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_cannot_be_created_with_invalid_email() {
    match User::now_with_email_and_password(String::from("invalid-email"), String::from("password"))
    {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_cannot_be_created_without_special_character() {
    match User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Password1"),
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
    )
    .unwrap();
    let hasher = SchemeAwareHasher::default();
    user.hash_password(&hasher);

    assert_eq!(user.verify_password(&hasher, "Iknow#othing1"), true);
}
