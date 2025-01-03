use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn it_creates_user() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = format!("jon{}@snow.test", uuid::Uuid::new_v4());
    let role_name = format!("USER_CLI_{}", uuid::Uuid::new_v4());

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
    let email = format!("jon{}@snow.test", uuid::Uuid::new_v4());
    let role_name = format!("USER_CLI_{}", uuid::Uuid::new_v4());

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
    let email = format!("jon{}@snow.test", uuid::Uuid::new_v4());
    let role_name = format!("USER_CLI_{}", uuid::Uuid::new_v4());

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
        .stdout(predicate::str::contains("Error NotFound"));
}

#[test]
fn it_deletes_user_by_email() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = format!("jon{}@snow.test", uuid::Uuid::new_v4());
    let role_name = format!("USER_CLI_{}", uuid::Uuid::new_v4());

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
fn it_assigns_role_to_user() {
    let mut create_cmd = Command::cargo_bin("app").unwrap();
    let mut create_role_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_cmd = Command::cargo_bin("app").unwrap();
    let mut delete_role_cmd = Command::cargo_bin("app").unwrap();
    let email = format!("jon{}@snow.test", uuid::Uuid::new_v4());
    let role_suffix = uuid::Uuid::new_v4();
    let role_name = format!("USER_CLI_{}", &role_suffix);

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
        .stdout(predicate::str::contains(format!(
            "roles (USER_CLI_{})",
            &role_suffix
        )));

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
    let role_name = format!("USER_CLI_{}", uuid::Uuid::new_v4());

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
    let role_name = format!("USER_CLI_{}", uuid::Uuid::new_v4());

    cmd.arg("init-restricted-role")
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

#[test]
fn it_checks_rabbitmq_connection() {
    let mut cmd = Command::cargo_bin("app").unwrap();

    cmd.arg("check-rabbitmq-connection").assert().success();
}

#[test]
fn it_consumes_rabbitmq_messages() {
    let mut cmd = Command::cargo_bin("app").unwrap();

    cmd.arg("consume-rabbitmq-messages")
        .arg("-e")
        .arg("test_exchange")
        .arg("-d")
        .arg("true")
        .assert()
        .success();
}
