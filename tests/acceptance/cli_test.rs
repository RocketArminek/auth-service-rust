use crate::utils::runners::{run_cli_test, run_cli_test_with_default};
use assert_cmd::prelude::*;
use auth_service::domain::crypto::SchemeAwareHasher;
use auth_service::domain::role::Role;
use auth_service::domain::user::{PasswordHandler, User};
use predicates::prelude::*;

#[tokio::test]
async fn it_creates_user() {
    run_cli_test_with_default(|c| async move {
        let email = "jon@snow.com";
        let password = "Iknow#othing1";
        let role = Role::now("SOME_AWESOME_ROLE".to_string()).unwrap();
        c.role_repository.lock().await.save(&role).await.unwrap();
        let mut cmd = c.cf.create("app").unwrap();

        cmd.arg("create-user")
            .arg("--email")
            .arg(email)
            .arg("--password")
            .arg(password)
            .arg("--role")
            .arg(&role.name)
            .assert()
            .success()
            .stdout(predicate::str::contains("User created:"))
            .stdout(predicate::str::contains(email));
    })
    .await;
}

#[tokio::test]
async fn it_checks_password_of_the_account() {
    run_cli_test_with_default(|c| async move {
        let mut cmd = c.cf.create("app").unwrap();
        let role = Role::now("SOME_AWESOME_ROLE".to_string()).unwrap();
        c.role_repository.lock().await.save(&role).await.unwrap();

        let email = "jon@snow.com";
        let password = "Iknow#othing1";
        let mut user = User::now_with_email_and_password(
            email.to_string(),
            password.to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        user.add_role(role);
        c.user_repository.lock().await.save(&user).await.unwrap();

        cmd.arg("check-password")
            .arg("--email")
            .arg(email)
            .arg("--password")
            .arg(password)
            .assert()
            .success()
            .stdout(predicate::str::contains("password is correct"))
            .stdout(predicate::str::contains(email));
    })
    .await
}

#[tokio::test]
async fn it_gets_user_by_email() {
    run_cli_test_with_default(|c| async move {
        let mut cmd = c.cf.create("app").unwrap();
        let role = Role::now("SOME_AWESOME_ROLE".to_string()).unwrap();
        c.role_repository.lock().await.save(&role).await.unwrap();

        let email = "jon@snow.com";
        let password = "Iknow#othing1";
        let mut user = User::now_with_email_and_password(
            email.to_string(),
            password.to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        user.add_role(role);
        c.user_repository.lock().await.save(&user).await.unwrap();

        cmd.arg("get-user-by-email")
            .arg("--email")
            .arg(email)
            .assert()
            .success()
            .stdout(predicate::str::contains("User found:"))
            .stdout(predicate::str::contains(email));
    })
    .await;
}

#[tokio::test]
async fn it_cannot_get_not_existing_user() {
    run_cli_test_with_default(|c| async move {
        let mut cmd = c.cf.create("app").unwrap();
        let email = "some@email.test";

        cmd.arg("get-user-by-email")
            .arg("--email")
            .arg(email)
            .assert()
            .success()
            .stdout(predicate::str::contains("Error NotFound"));
    })
    .await;
}

#[tokio::test]
async fn it_deletes_user_by_email() {
    run_cli_test_with_default(|c| async move {
        let mut cmd = c.cf.create("app").unwrap();
        let role = Role::now("SOME_AWESOME_ROLE".to_string()).unwrap();
        c.role_repository.lock().await.save(&role).await.unwrap();

        let email = "jon@snow.com";
        let password = "Iknow#othing1";
        let mut user = User::now_with_email_and_password(
            email.to_string(),
            password.to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        user.add_role(role);
        c.user_repository.lock().await.save(&user).await.unwrap();

        cmd.arg("delete-user-by-email")
            .arg("--email")
            .arg(email)
            .assert()
            .success()
            .stdout(predicate::str::contains(format!(
                "User deleted for {}",
                email
            )))
            .stdout(predicate::str::contains(email));
    })
    .await;
}

#[tokio::test]
async fn it_does_not_create_user_with_invalid_email() {
    run_cli_test_with_default(|c| async move {
        let mut cmd = c.cf.create("app").unwrap();

        cmd.arg("create-user")
            .arg("--email")
            .arg("test-user")
            .arg("--password")
            .arg("Iknow#othing1")
            .assert()
            .failure()
            .stderr(predicate::str::contains("Invalid email:"));
    })
    .await;
}

#[tokio::test]
async fn it_assigns_role_to_user() {
    run_cli_test_with_default(|c| async move {
        let mut cmd = c.cf.create("app").unwrap();
        let role = Role::now("SOME_AWESOME_ROLE".to_string()).unwrap();
        c.role_repository.lock().await.save(&role).await.unwrap();

        let email = "jon@snow.com";
        let password = "Iknow#othing1";
        let mut user = User::now_with_email_and_password(
            email.to_string(),
            password.to_string(),
            None,
            None,
            Some(true),
        )
        .unwrap();
        user.hash_password(&SchemeAwareHasher::default()).unwrap();
        c.user_repository.lock().await.save(&user).await.unwrap();

        cmd.arg("assign-role")
            .arg("--email")
            .arg(email)
            .arg("--role")
            .arg(&role.name)
            .assert()
            .success()
            .stdout(predicate::str::contains("Role assigned"))
            .stdout(predicate::str::contains(role.name));
    })
    .await;
}

#[tokio::test]
async fn it_gets_role() {
    run_cli_test_with_default(|c| async move {
        let mut cmd = c.cf.create("app").unwrap();
        let role = Role::now("SOME_AWESOME_ROLE".to_string()).unwrap();
        c.role_repository.lock().await.save(&role).await.unwrap();

        cmd.arg("get-role")
            .arg("--name")
            .arg(&role.name)
            .assert()
            .success()
            .stdout(predicate::str::contains(&role.name));
    })
    .await;
}

#[tokio::test]
async fn it_initializes_auth_owner_role() {
    let role_name = "AWESOME";
    run_cli_test(
        |c| {
            c.app.restricted_role_name(role_name.to_string());
        },
        |c| async move {
            let mut cmd = c.cf.create("app").unwrap();
            let mut get_role_cmd = c.cf.create("app").unwrap();

            cmd.arg("init-restricted-role").assert().success();

            get_role_cmd
                .arg("get-role")
                .arg("--name")
                .arg(role_name)
                .assert()
                .success()
                .stdout(predicate::str::contains(role_name));
        },
    )
    .await;
}

#[tokio::test]
async fn it_checks_rabbitmq_connection() {
    run_cli_test_with_default(|c| async move {
        let mut cmd = c.cf.create("app").unwrap();

        cmd.arg("check-rabbitmq-connection").assert().success();
    })
    .await;
}

#[tokio::test]
async fn it_consumes_rabbitmq_messages() {
    let exchange_name = "awesome_exchange";

    run_cli_test(
        |c| {
            c.publisher
                .rabbitmq_exchange_name(exchange_name.to_string());
        },
        |c| async move {
            let mut cmd = c.cf.create("app").unwrap();

            cmd.arg("consume-rabbitmq-messages")
                .arg("-e")
                .arg(exchange_name)
                .arg("-d")
                .arg("true")
                .assert()
                .success();
        },
    )
    .await;
}
