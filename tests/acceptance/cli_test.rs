use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

//TODO how to clean up the database after each test?

#[test]
fn it_creates_user() {
    let mut create_cmd = Command::cargo_bin("cli").unwrap();
    let mut delete_cmd = Command::cargo_bin("cli").unwrap();
    let email = String::from("jon@snow.test");

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1");

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
}

#[test]
fn it_logs_into_account() {
    let mut create_cmd = Command::cargo_bin("cli").unwrap();
    let mut login_cmd = Command::cargo_bin("cli").unwrap();
    let mut delete_cmd = Command::cargo_bin("cli").unwrap();
    let email = String::from("jon9@snow.test");

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
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
}

#[test]
fn it_gets_user_by_email() {
    let mut create_cmd = Command::cargo_bin("cli").unwrap();
    let mut get_cmd = Command::cargo_bin("cli").unwrap();
    let mut delete_cmd = Command::cargo_bin("cli").unwrap();

    let email = String::from("jon1@snow.test");
    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
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
}

#[test]
fn it_cannot_get_not_existing_user() {
    let mut get_cmd = Command::cargo_bin("cli").unwrap();
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
    let mut create_cmd = Command::cargo_bin("cli").unwrap();
    let mut delete_cmd = Command::cargo_bin("cli").unwrap();
    let email = String::from("jon2@snow.test");

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
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
}

#[test]
fn it_does_not_create_user_with_invalid_email() {
    let mut cmd = Command::cargo_bin("cli").unwrap();

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
    let mut create_cmd = Command::cargo_bin("cli").unwrap();
    let mut assign_cmd = Command::cargo_bin("cli").unwrap();
    let mut delete_cmd = Command::cargo_bin("cli").unwrap();
    let email = String::from("jon11@snow.test");

    create_cmd
        .arg("create-user")
        .arg("--email")
        .arg(&email)
        .arg("--password")
        .arg("Iknow#othing1")
        .assert()
        .success();

    assign_cmd
        .arg("assign-role")
        .arg("--email")
        .arg(&email)
        .arg("--role")
        .arg("AUTH_OWNER")
        .assert()
        .success()
        .stdout(predicate::str::contains("Role assigned: AUTH_OWNER to jon11@snow.test"));

    delete_cmd
        .arg("delete-user-by-email")
        .arg("--email")
        .arg(&email)
        .assert()
        .success();
}

#[test]
fn it_initializes_auth_owner_role() {
    let mut cmd = Command::cargo_bin("cli").unwrap();

    cmd
        .arg("init-auth-owner-role")
        .assert()
        .success()
        .stdout(predicate::str::contains("Role already exists"));
}
