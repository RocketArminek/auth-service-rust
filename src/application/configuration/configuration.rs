use crate::application::configuration::app::{AppConfiguration, AppConfigurationBuilder};
use crate::application::configuration::database::{DatabaseConfiguration, DatabaseConfigurationBuilder};
use crate::application::configuration::message_publisher::{
    EnvNames, MessagePublisherConfiguration, MessagePublisherConfigurationBuilder,
};
use dotenvy::{dotenv, from_filename};
use std::collections::HashMap;
use std::fmt::Debug;

pub struct ConfigurationBuilder {
    pub app: AppConfigurationBuilder,
    pub db: DatabaseConfigurationBuilder,
    pub publisher: MessagePublisherConfigurationBuilder,
}

impl ConfigurationBuilder {
    pub fn new(
        app: AppConfigurationBuilder,
        db: DatabaseConfigurationBuilder,
        publisher: MessagePublisherConfigurationBuilder,
    ) -> Self {
        ConfigurationBuilder { app, db, publisher }
    }

    pub fn build(&self) -> Configuration {
        Configuration::new(self.app.build(), self.db.build(), self.publisher.build())
    }
}

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
        publisher: MessagePublisherConfiguration,
    ) -> Self {
        Configuration { app, db, publisher }
    }

    pub fn load<F>(loader: F) -> Self
    where
        F: FnOnce(
            AppConfigurationBuilder,
            DatabaseConfigurationBuilder,
            MessagePublisherConfigurationBuilder,
        ) -> (
            AppConfiguration,
            DatabaseConfiguration,
            MessagePublisherConfiguration,
        ),
    {
        let (app, db, publisher) = loader(
            AppConfigurationBuilder::new(),
            DatabaseConfigurationBuilder::new(),
            MessagePublisherConfigurationBuilder::new(),
        );

        Configuration { app, db, publisher }
    }

    pub fn envs(&self) -> HashMap<String, String> {
        let mut envs = HashMap::new();
        envs.extend(self.app.envs());
        envs.extend(self.db.envs());
        match &self.publisher {
            MessagePublisherConfiguration::Rabbitmq(config) => {
                envs.extend(config.envs());
                envs.insert(EnvNames::EVENT_DRIVEN.to_owned(), "true".to_string());
            }
            MessagePublisherConfiguration::None => {
                envs.insert(EnvNames::EVENT_DRIVEN.to_owned(), "false".to_string());
            }
        }

        envs
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
        Configuration::load(|mut app, mut db, mut publisher| {
            from_filename("../../../.env.local").or(dotenv()).ok();

            (
                app.load_env().build(),
                db.load_env().build(),
                publisher.load_env().build(),
            )
        })
    }
}
