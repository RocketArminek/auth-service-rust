use auth_service::domain::role::Role;
use chrono::Utc;
use uuid::Uuid;

#[test]
fn it_can_be_created() {
    let role = Role::new(Uuid::new_v4(), "SUPER_ADMIN".to_string(), Utc::now()).unwrap();

    assert_eq!(role.name, "SUPER_ADMIN".to_string());
    assert!(!role.id.is_nil());
}

#[test]
fn it_cannot_be_created_with_empty_name() {
    match Role::new(Uuid::new_v4(), "".to_string(), Utc::now()) {
        Ok(_) => panic!("Role creation should fail"),
        Err(e) => e,
    };
}

#[test]
fn it_can_be_created_now() {
    let role = Role::now("SUPER_ADMIN".to_string()).unwrap();

    assert_eq!(role.name, "SUPER_ADMIN".to_string());
    assert!(!role.id.is_nil());
}
