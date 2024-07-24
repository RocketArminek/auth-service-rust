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
    let email = String::from("jon@snow.test");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg("USER_CLI_1")
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg("USER_CLI_1");

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
        .arg("USER_CLI_1")
        .assert()
        .success();
}

#[test]
fn it_logs_into_account() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut login_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = String::from("jon9@snow.test");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg("USER_CLI_2")
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg("USER_CLI_2")
        .assert()
        .success();

    login_cmd
        .arg("login")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .assert()
        .success()
        .stdout(predicate::str::contains("User logged in:"))
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
        .arg("USER_CLI_2")
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

    let email = String::from("jon1@snow.test");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg("USER_CLI_3")
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg("USER_CLI_3")
        .assert()
        .success();

    get_cmd.arg("get-user-by-email").arg("--email").arg(&email);

    get_cmd
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
        .arg("USER_CLI_3")
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
    let email = String::from("jon2@snow.test");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg("USER_CLI_4")
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg("USER_CLI_4")
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
        .arg("USER_CLI_4")
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
    let email = String::from("jon131@snow.test");

    create_role_cmd
        .arg("create-role")
        .arg("--name")
        .arg("USER_CLI_5")
        .assert()
        .success();

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .arg("--role")
        .arg("USER_CLI_5")
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
        .arg("USER_CLI_5")
        .assert()
        .success();
}

#[test]
fn it_initializes_auth_owner_role() {
    let mut cmd = Command::cargo_bin("app").unwrap();

    cmd
        .arg("init-restricted-role")
        .assert()
        .success();
}
