use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::error::UserError;
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
fn test_invalid_email_formats() {
    let invalid_emails = vec![
        "test",
        "test@",
        "@example.com",
        "test@.com",
        "test@example.",
        "test@example..com",
        "test@exam ple.com",
        "test@@example.com",
        "test@.example.com",
        "test@example..",
        "test@..example.com",
        "test@example@com",
        "@example.com",
        "test@",
        "test",
        "test@example",
    ];

    for email in invalid_emails {
        let result = User::now_with_email_and_password(
            email.to_string(),
            "Password1#".to_string(),
            None,
            None,
            Some(true),
        );
        assert!(
            matches!(result, Err(UserError::InvalidEmail { email: e }) if e == email),
            "Email '{}' should be invalid",
            email
        );
    }
}

#[test]
fn test_valid_email_formats() {
    let valid_emails = vec![
        "test@example.com",
        "test.name@example.com",
        "test+name@example.com",
        "test@sub.example.com",
        "test@sub.sub.example.com",
        "test@example-site.com",
        "test123@example.com",
        "TEST@EXAMPLE.COM",
        "test@example.co.uk",
        "perf_test_1736365298278@example.com",
    ];

    for email in valid_emails {
        let result = User::now_with_email_and_password(
            email.to_string(),
            "Password1#".to_string(),
            None,
            None,
            Some(true),
        );
        assert!(result.is_ok(), "Email '{}' should be valid", email);
    }
}

#[test]
fn test_password_all_requirements() {
    let valid_passwords = vec![
        "Password1#",
        "Complex1@Password",
        "Abcd123!@#",
        "Test@1234",
        "Pa$$w0rd",
        "Secure&123",
    ];

    for password in valid_passwords {
        let result = User::now_with_email_and_password(
            "test@example.com".to_string(),
            password.to_string(),
            None,
            None,
            Some(true),
        );
        assert!(result.is_ok(), "Password {} should be valid", password);
    }
}

#[test]
fn test_password_all_requirements_during_password_change() {
    let valid_passwords = vec![
        "Password1#",
        "Complex1@Password",
        "Abcd123!@#",
        "Test@1234",
        "Pa$$w0rd",
        "Secure&123",
    ];

    for password in valid_passwords {
        let mut user = User::now_with_email_and_password(
            "test@example.com".to_string(),
            "P#assword*123".to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        let result = user.change_password(password, &SchemeAwareHasher::default());

        assert!(result.is_ok(), "Password {} should be valid", password);
    }
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
fn it_cannot_change_to_password_without_special_character() {
    let user = User::now_with_email_and_password(
        String::from("test@test.com"),
        String::from("Password1#*123"),
        Some(String::from("Jon")),
        Some(String::from("Snow")),
        Some(true),
    );

    let result = user
        .unwrap()
        .change_password("Password1", &SchemeAwareHasher::default());

    match result {
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
    user.hash_password(&hasher).unwrap();

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
