use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn it_returns_hello_world() {
    let mut cmd = Command::cargo_bin("cli").unwrap();

    cmd.arg("--name").arg("world");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Hello world!"));
}
