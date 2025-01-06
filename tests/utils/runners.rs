use std::future::Future;
use auth_service::infrastructure::database::{create_pool};
use auth_service::infrastructure::repository::{create_role_repository, create_user_repository};
use dotenv::{dotenv, from_filename};
use auth_service::infrastructure::message_publisher::{create_message_publisher};
use uuid::Uuid;
use auth_service::application::configuration::{ConfigurationBuilder};
use crate::utils::config::init_test_config_builder;
use crate::utils::context::IntegrationTestContext;
use crate::utils::db::drop_database;
use crate::utils::events::setup_test_consumer;
use crate::utils::server::create_test_server;

const NONE_CONFIGURATOR: fn(&mut ConfigurationBuilder) = |_| {};

pub async fn run_integration_test<F, Fut, C>(
    configurator: C,
    test: F,
) where
    F: Fn(IntegrationTestContext) -> Fut,
    Fut: Future<Output = ()>,
    C: FnOnce(&mut ConfigurationBuilder)
{
    from_filename(".env.test").or(dotenv()).ok();
    let case = Uuid::new_v4().to_string().replace("-", "_");
    let builder = init_test_config_builder(
        &case,
        configurator
    );

    let config = builder.build();

    let pool = create_pool(config.db()).await.unwrap();
    pool.migrate().await;
    let user_repository = create_user_repository(pool.clone());
    let role_repository = create_role_repository(pool.clone());

    let message_publisher = create_message_publisher(config.publisher()).await;
    let (_, consumer, _) = setup_test_consumer(config.publisher()).await;

    let server = create_test_server(
        &config,
        user_repository.clone(),
        role_repository.clone(),
        message_publisher
    ).await;

    test(
        IntegrationTestContext::new(
            user_repository,
            role_repository,
            server,
            consumer,
        )
    )
        .await;

    drop_database(&pool, config.db().database_url()).await;
}

pub async fn run_integration_test_with_default<F, Fut>(test: F)
where
    F: Fn(IntegrationTestContext) -> Fut,
    Fut: Future<Output = ()>,
{
    run_integration_test(NONE_CONFIGURATOR, test).await;
}
