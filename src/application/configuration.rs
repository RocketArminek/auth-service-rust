use dotenv::{dotenv, from_filename};
use std::fmt::{Debug};
use crate::application::app_configuration::{AppConfiguration, AppConfigurationBuilder};
use crate::application::database_configuration::{DatabaseConfiguration, DatabaseConfigurationBuilder};
use crate::application::message_publisher_configuration::{MessagePublisherConfiguration, MessagePublisherConfigurationBuilder};

#[derive(Debug, Clone)]
pub struct Configuration {
    app: AppConfiguration,
    db: DatabaseConfiguration,
    publisher: MessagePublisherConfiguration,
}

impl Configuration {
    pub fn new(
        app: AppConfiguration,
        db: DatabaseConfiguration,
        publisher: MessagePublisherConfiguration
    ) -> Self {
        Configuration { app, db, publisher }
    }

    pub fn load<F>(loader: F, dot_env_file_name: Option<&str>) -> Self
    where
        F: FnOnce(
            AppConfigurationBuilder,
            DatabaseConfigurationBuilder,
            MessagePublisherConfigurationBuilder
        ) -> (AppConfiguration, DatabaseConfiguration, MessagePublisherConfiguration),
    {
        from_filename(dot_env_file_name.unwrap_or(".env.local"))
            .or(dotenv())
            .ok();
        let (app, db, publisher) =
            loader(
                AppConfigurationBuilder::new(),
                DatabaseConfigurationBuilder::new(),
                MessagePublisherConfigurationBuilder::new(),
            );

        Configuration { app, db, publisher }
    }

    pub fn app(&self) -> &AppConfiguration {
        &self.app
    }

    pub fn db(&self) -> &DatabaseConfiguration {
        &self.db
    }

    pub fn publisher(&self) -> &MessagePublisherConfiguration {
        &self.publisher
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration::load(
            |mut app, mut db, mut publisher|
                (app.load_env().build(), db.load_env().build(), publisher.load_env().build()),
            None
        )
    }
}
