use auth_service::application::config::app::AppConfigurationBuilder;
use auth_service::application::config::configuration::ConfigurationBuilder;
use auth_service::application::config::database::DatabaseConfigurationBuilder;
use auth_service::application::config::message_publisher::MessagePublisherConfigurationBuilder;

pub fn init_test_publisher_configuration_builder(
    test_case_id: &str,
    configurator: impl FnOnce(&mut MessagePublisherConfigurationBuilder),
) -> MessagePublisherConfigurationBuilder {
    let mut builder = MessagePublisherConfigurationBuilder::new();
    builder.load_env();
    builder.rabbitmq_exchange_name(format!(
        "{}_{}",
        builder
            .rabbitmq_exchange_name
            .clone()
            .unwrap_or(test_case_id.to_string()),
        test_case_id
    ));
    configurator(&mut builder);

    builder
}

pub fn init_test_database_configuration_builder(
    test_case_id: &str,
    configurator: impl FnOnce(&mut DatabaseConfigurationBuilder),
) -> DatabaseConfigurationBuilder {
    let mut builder = DatabaseConfigurationBuilder::new();
    builder.load_env();
    builder.database_url(format!(
        "{}_{}",
        builder
            .database_url
            .clone()
            .unwrap_or(test_case_id.to_string()),
        test_case_id
    ));
    configurator(&mut builder);

    builder
}

pub fn init_test_app_configuration_builder(
    _test_case_id: &str,
    _configurator: impl FnOnce(&mut AppConfigurationBuilder),
) -> AppConfigurationBuilder {
    let mut builder = AppConfigurationBuilder::new();
    builder.load_env();

    builder
}

pub fn init_test_config_builder(
    test_case_id: &str,
    configurator: impl FnOnce(&mut ConfigurationBuilder),
) -> ConfigurationBuilder {
    let mut builder = ConfigurationBuilder::new(
        init_test_app_configuration_builder(test_case_id, |_| {}),
        init_test_database_configuration_builder(test_case_id, |_| {}),
        init_test_publisher_configuration_builder(test_case_id, |_| {}),
    );

    configurator(&mut builder);

    builder
}
