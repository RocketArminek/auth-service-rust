use auth_service::application::app_configuration::AppConfigurationBuilder;
use auth_service::application::configuration::ConfigurationBuilder;
use auth_service::application::database_configuration::DatabaseConfigurationBuilder;
use auth_service::application::message_publisher_configuration::MessagePublisherConfigurationBuilder;

pub fn init_test_config_builder(
    test_case_id: &str,
    configurator: impl FnOnce(&mut ConfigurationBuilder)
) -> ConfigurationBuilder {
    let mut builder = ConfigurationBuilder::new(
        AppConfigurationBuilder::new(),
        DatabaseConfigurationBuilder::new(),
        MessagePublisherConfigurationBuilder::new(),
    );

    builder.app.load_env();
    builder.db.load_env();
    builder.publisher.load_env();

    builder.db.database_url(
        format!("{}_{}", builder.db.database_url.clone().unwrap(), test_case_id)
    );

    builder.publisher.rabbitmq_exchange_name(format!(
        "{}_{}",
        builder.publisher.rabbitmq_exchange_name.clone().unwrap(),
        test_case_id
    ));

    configurator(&mut builder);

    builder
}
