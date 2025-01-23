use auth_service::domain::permission::{Permission};
use chrono::Utc;
use uuid::Uuid;
use auth_service::domain::error::PermissionError;

#[test]
fn it_can_be_created() {
    let permission = Permission::new(
        Uuid::new_v4(),
        "create_user".to_string(),
        "user_management".to_string(),
        Some("Allows creating new users".to_string()),
        false,
        Utc::now(),
    )
    .unwrap();

    assert_eq!(permission.name, "create_user");
    assert_eq!(permission.group_name, "user_management");
    assert_eq!(
        permission.description,
        Some("Allows creating new users".to_string())
    );
    assert_eq!(permission.is_system, false);
    assert_eq!(permission.id.is_nil(), false);
}

#[test]
fn it_can_be_created_now() {
    let permission = Permission::now(
        "delete_user".to_string(),
        "user_management".to_string(),
        Some("Allows deleting users".to_string()),
    )
    .unwrap();

    assert_eq!(permission.name, "delete_user");
    assert_eq!(permission.group_name, "user_management");
    assert_eq!(
        permission.description,
        Some("Allows deleting users".to_string())
    );
    assert_eq!(permission.is_system, false);
    assert_eq!(permission.id.is_nil(), false);
}

#[test]
fn it_cannot_be_created_with_empty_name() {
    let result = Permission::new(
        Uuid::new_v4(),
        "".to_string(),
        "user_management".to_string(),
        None,
        false,
        Utc::now(),
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), PermissionError::EmptyName);
}

#[test]
fn it_cannot_be_created_with_empty_group_name() {
    let result = Permission::new(
        Uuid::new_v4(),
        "create_user".to_string(),
        "".to_string(),
        None,
        false,
        Utc::now(),
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), PermissionError::EmptyGroupName);
}

#[test]
fn it_cannot_be_created_with_whitespace_name() {
    let result = Permission::new(
        Uuid::new_v4(),
        " ".to_string(),
        "user_management".to_string(),
        None,
        false,
        Utc::now(),
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), PermissionError::EmptyName);
}

#[test]
fn it_cannot_be_created_with_whitespace_group_name() {
    let result = Permission::new(
        Uuid::new_v4(),
        "create_user".to_string(),
        " ".to_string(),
        None,
        false,
        Utc::now(),
    );

    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), PermissionError::EmptyGroupName);
}
