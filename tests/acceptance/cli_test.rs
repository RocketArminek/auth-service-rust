use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn it_creates_user() {
    let mut cmd = Command::cargo_bin("cli").unwrap();

    cmd.arg("create-user").arg("--email").arg("jon@snow.test");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("User created:"))
        .stdout(predicate::str::contains("jon@snow.test"));
}

#[test]
fn it_does_not_create_user_with_invalid_email() {
    let mut cmd = Command::cargo_bin("cli").unwrap();

    cmd.arg("create-user").arg("--email").arg("test-user");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid email:"));
}
