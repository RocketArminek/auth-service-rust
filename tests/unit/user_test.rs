use auth_service::domain::user::User;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[test]
fn it_can_be_created() {
    let user = create_user(
        Uuid::new_v4(),
        String::from("test@test.com"),
        String::from("pass"),
        Utc::now(),
    );

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

fn create_user(id: Uuid, email: String, password: String, created_at: DateTime<Utc>) -> User {
    let user = User::new(id, email, password, created_at);

    match user {
        Ok(x) => x,
        Err(_) => panic!("User creation failed"),
    }
}
