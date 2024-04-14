use uuid::Uuid;
use auth_service::domain::user::User;
#[test]
fn it_can_be_created() {
    let user = create_user(Uuid::new_v4(), String::from("test@test.com"));

    assert_eq!(user.email, String::from("test@test.com"));
    assert_eq!(user.roles, vec![String::from("ROLE_USER")]);
    assert_eq!(user.id.is_nil(), false);
}

#[test]
fn it_cannot_be_created_with_empty_email() {
    match User::new(Uuid::new_v4(), String::from("")) {
        Ok(_) => panic!("User creation should fail"),
        Err(e) => e,
    };
}

fn create_user(id: Uuid, email: String) -> User {
    let user = User::new(id, email);

    match user {
        Ok(x) => x,
        Err(_) => panic!("User creation failed"),
    }
}
