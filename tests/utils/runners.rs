use crate::utils::cli::CommandFactory;
use crate::utils::config::{
    init_test_config_builder, init_test_database_configuration_builder,
    init_test_publisher_configuration_builder,
};
use crate::utils::context::{
    AcceptanceTestContext, CliTestContext, DatabaseTestContext, PublisherTestContext,
};
use crate::utils::db::drop_database;
use crate::utils::events::setup_test_consumer;
use crate::utils::server::create_test_server;
use auth_service::application::service::auth_service::create_auth_service;
use auth_service::application::config::configuration::ConfigurationBuilder;
use auth_service::application::config::database::DatabaseConfigurationBuilder;
use auth_service::application::config::message_publisher::MessagePublisherConfigurationBuilder;
use auth_service::infrastructure::database::create_pool;
use auth_service::infrastructure::message_publisher::create_message_publisher;
use auth_service::infrastructure::repository::{
    create_role_repository, create_session_repository, create_user_repository,
};
use dotenvy::{dotenv, from_filename};
use std::future::Future;
use uuid::Uuid;

const NONE_CONFIGURATOR: fn(&mut ConfigurationBuilder) = |_| {};
const NONE_MESSAGE_PUBLISHER_CONFIGURATOR: fn(&mut MessagePublisherConfigurationBuilder) = |_| {};
const NONE_DATABASE_CONFIGURATOR: fn(&mut DatabaseConfigurationBuilder) = |_| {};

pub async fn run_database_test_with_default<F, Fut>(test: F)
where
    F: Fn(DatabaseTestContext) -> Fut,
    Fut: Future<Output = ()>,
{
    run_database_test(NONE_DATABASE_CONFIGURATOR, test).await;
}

pub async fn run_database_test<F, Fut, C>(configurator: C, test: F)
where
    F: Fn(DatabaseTestContext) -> Fut,
    Fut: Future<Output = ()>,
    C: FnOnce(&mut DatabaseConfigurationBuilder),
{
    from_filename(".env.test").or(dotenv()).ok();
    let case = Uuid::new_v4().to_string().replace("-", "_");
    let builder = init_test_database_configuration_builder(&case, configurator);

    let config = builder.build();

    let pool = create_pool(&config).await.unwrap();
    pool.migrate().await;
    let user_repository = create_user_repository(pool.clone());
    let role_repository = create_role_repository(pool.clone());
    let session_repository = create_session_repository(pool.clone());

    test(DatabaseTestContext::new(
        user_repository,
        role_repository,
        session_repository,
    ))
    .await;

    drop_database(&pool, config.database_url()).await;
}

pub async fn run_message_publisher_test_with_default<F, Fut>(test: F)
where
    F: Fn(PublisherTestContext) -> Fut,
    Fut: Future<Output = ()>,
{
    run_message_publisher_test(NONE_MESSAGE_PUBLISHER_CONFIGURATOR, test).await;
}

pub async fn run_message_publisher_test<F, Fut, C>(configurator: C, test: F)
where
    F: Fn(PublisherTestContext) -> Fut,
    Fut: Future<Output = ()>,
    C: FnOnce(&mut MessagePublisherConfigurationBuilder),
{
    from_filename(".env.test").or(dotenv()).ok();
    let case = Uuid::new_v4().to_string().replace("-", "_");
    let builder = init_test_publisher_configuration_builder(&case, configurator);

    let config = builder.build();

    let message_publisher = create_message_publisher(&config).await;
    let (_, consumer, _) = setup_test_consumer(&config).await;

    test(PublisherTestContext::new(message_publisher, consumer)).await
}

pub async fn run_integration_test_with_default<F, Fut>(test: F)
where
    F: Fn(AcceptanceTestContext) -> Fut,
    Fut: Future<Output = ()>,
{
    run_integration_test(NONE_CONFIGURATOR, test).await;
}

pub async fn run_integration_test<F, Fut, C>(configurator: C, test: F)
where
    F: Fn(AcceptanceTestContext) -> Fut,
    Fut: Future<Output = ()>,
    C: FnOnce(&mut ConfigurationBuilder),
{
    from_filename(".env.test").or(dotenv()).ok();
    let case = Uuid::new_v4().to_string().replace("-", "_");
    let builder = init_test_config_builder(&case, configurator);

    let config = builder.build();

    let pool = create_pool(config.db()).await.unwrap();
    pool.migrate().await;
    let user_repository = create_user_repository(pool.clone());
    let role_repository = create_role_repository(pool.clone());
    let session_repository = create_session_repository(pool.clone());

    let message_publisher = create_message_publisher(config.publisher()).await;
    let (_, consumer, _) = setup_test_consumer(config.publisher()).await;

    let auth_service = create_auth_service(
        config.app(),
        user_repository.clone(),
        session_repository.clone(),
    );

    let server = create_test_server(
        &config,
        user_repository.clone(),
        role_repository.clone(),
        session_repository.clone(),
        message_publisher,
        auth_service,
    )
    .await;

    test(AcceptanceTestContext::new(
        user_repository,
        role_repository,
        session_repository,
        server,
        consumer,
    ))
    .await;

    drop_database(&pool, config.db().database_url()).await;
}

pub async fn run_cli_test_with_default<F, Fut>(test: F)
where
    F: Fn(CliTestContext) -> Fut,
    Fut: Future<Output = ()>,
{
    run_cli_test(NONE_CONFIGURATOR, test).await;
}

pub async fn run_cli_test<F, Fut, C>(configurator: C, test: F)
where
    F: Fn(CliTestContext) -> Fut,
    Fut: Future<Output = ()>,
    C: FnOnce(&mut ConfigurationBuilder),
{
    from_filename(".env.test").or(dotenv()).ok();
    let case = Uuid::new_v4().to_string().replace("-", "_");
    let builder = init_test_config_builder(&case, configurator);

    let config = builder.build();

    let command_factory = CommandFactory::new(&config);

    let pool = create_pool(config.db()).await.unwrap();
    pool.migrate().await;
    let user_repository = create_user_repository(pool.clone());
    let role_repository = create_role_repository(pool.clone());

    test(CliTestContext::new(
        user_repository,
        role_repository,
        command_factory,
    ))
    .await;

    drop_database(&pool, config.db().database_url()).await;
}
