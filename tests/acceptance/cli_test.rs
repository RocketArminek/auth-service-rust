use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

//TODO how to clean up the database after each test?

#[test]
fn it_creates_user() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = String::from("jon1@snow.test");
    let role_name = String::from("USER_CLI_1");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg(&role_name);

    create_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("User created:"))
        .stdout(predicate::str::contains(&email));

    delete_cmd
        .arg("delete-user-by-email")
        .arg("--email")
        .arg(&email)
        .assert()
        .success();

    delete_role_cmd
        .arg("delete-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();
}

#[test]
fn it_checks_password_of_the_account() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut check_password_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = String::from("jon2@snow.test");
    let role_name = String::from("USER_CLI_2");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg(&role_name)
        .assert()
        .success();

    check_password_cmd
        .arg("check-password")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .assert()
        .success()
        .stdout(predicate::str::contains("password is correct"))
        .stdout(predicate::str::contains(&email));

    delete_cmd
        .arg("delete-user-by-email")
        .arg("--email")
        .arg(&email)
        .assert()
        .success();

    delete_role_cmd
        .arg("delete-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();
}

#[test]
fn it_gets_user_by_email() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut get_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = String::from("jon3@snow.test");
    let role_name = String::from("USER_CLI_3");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg(&role_name)
        .assert()
        .success();

    get_cmd
        .arg("get-user-by-email")
        .arg("--email")
        .arg(&email)
        .assert()
        .success()
        .stdout(predicate::str::contains("User found:"))
        .stdout(predicate::str::contains(&email));

    delete_cmd
        .arg("delete-user-by-email")
        .arg("--email")
        .arg(&email)
        .assert()
        .success();

    delete_role_cmd
        .arg("delete-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();
}

#[test]
fn it_cannot_get_not_existing_user() {
    let mut get_cmd = Command::cargo_bin("app").unwrap();
    let email = String::from("some@email.test");
    get_cmd.arg("get-user-by-email").arg("--email").arg(&email);

    get_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "User not found for {}",
            &email
        )));
}

#[test]
fn it_deletes_user_by_email() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = String::from("jon4@snow.test");
    let role_name = String::from("USER_CLI_4");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg(&role_name)
        .assert()
        .success();

    delete_cmd
        .arg("delete-user-by-email")
        .arg("--email")
        .arg(&email);

    delete_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "User deleted for {}",
            &email
        )))
        .stdout(predicate::str::contains(&email));

    delete_role_cmd
        .arg("delete-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();
}

#[test]
fn it_does_not_create_user_with_invalid_email() {
    let mut cmd = Command::cargo_bin("app").unwrap();

    cmd.arg("create-user")
        .arg("--email")
        .arg("test-user")
        .arg("--password")
        .arg("Iknow#othing1");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid email:"));
}

#[test]
fn it_assign_role_to_user() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = String::from("jon5@snow.test");
    let role_name = String::from("USER_CLI_5");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg(&role_name)
        .assert()
        .success()
        .stdout(predicate::str::contains("roles (USER_CLI_5)"));

    delete_cmd
        .arg("delete-user-by-email")
        .arg("--email")
        .arg(&email)
        .assert()
        .success();

    delete_role_cmd
        .arg("delete-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();
}

#[test]
fn it_gets_role() {
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut get_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let role_name = String::from("USER_CLI_6");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();

    get_role_cmd
        .arg("get-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();

    delete_role_cmd
        .arg("delete-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();
}

#[test]
fn it_initializes_auth_owner_role() {
    let mut cmd = Command::cargo_bin("app").unwrap();
    let mut get_role_cmd = Command::cargo_bin("app").unwrap();
    let role_name = String::from("USER_CLI_7");

    cmd
        .arg("init-restricted-role")
        .env("RESTRICTED_ROLE_PREFIX", &role_name)
        .assert()
        .success();

    get_role_cmd
        .arg("get-role")
        .arg("--name")
        .arg(&role_name)
        .assert()
        .success();
}
