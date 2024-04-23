use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

//TODO how to clean up the database after each test?

#[test]
fn it_creates_user() {
    let mut create_cmd = Command::cargo_bin("cli").unwrap();
    let mut delete_cmd = Command::cargo_bin("cli").unwrap();
    let email = String::from("jon@snow.test");

    create_cmd.arg("create-user").arg("--email").arg(&email).arg("--password").arg("123456");

    create_cmd.assert()
        .success()
        .stdout(predicate::str::contains("User created:"))
        .stdout(predicate::str::contains(&email));

    delete_cmd.arg("delete-user-by-email").arg("--email").arg(&email).assert().success();
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
        .arg("123456")
        .assert()
        .success();

    get_cmd
        .arg("get-user-by-email")
        .arg("--email")
        .arg(&email);

    get_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("User found:"))
        .stdout(predicate::str::contains(&email));

    delete_cmd.arg("delete-user-by-email").arg("--email").arg(&email).assert().success();
}

#[test]
fn it_cannot_get_not_existing_user() {
    let mut get_cmd = Command::cargo_bin("cli").unwrap();
    let email = String::from("some@email.test");
    get_cmd
        .arg("get-user-by-email")
        .arg("--email")
        .arg(&email);

    get_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("User not found for {}", &email)));
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
        .arg("123456")
        .assert()
        .success();

    delete_cmd.arg("delete-user-by-email").arg("--email").arg(&email);

    delete_cmd.assert()
        .success()
        .stdout(predicate::str::contains(format!("User deleted for {}", &email)))
        .stdout(predicate::str::contains(&email));
}

#[test]
fn it_does_not_create_user_with_invalid_email() {
    let mut cmd = Command::cargo_bin("cli").unwrap();

    cmd.arg("create-user").arg("--email").arg("test-user").arg("--password").arg("123456");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid email:"));
}
