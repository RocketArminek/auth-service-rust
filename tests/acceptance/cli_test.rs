use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn it_returns_hello_world() {
    let mut cmd = Command::cargo_bin("cli").unwrap();

    cmd.arg("create-user").arg("--email").arg("jon@snow.test");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("User created:"))
        .stdout(predicate::str::contains("jon@snow.test"));
}

#[test]
fn it_cannot_be_created_with_empty_email() {
    let mut cmd = Command::cargo_bin("cli").unwrap();

    cmd.arg("create-user").arg("--email").arg("test-user");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid email"));
}
