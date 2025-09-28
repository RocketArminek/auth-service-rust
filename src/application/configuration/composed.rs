use crate::application::configuration::app::{AppConfiguration, AppConfigurationBuilder};
use crate::application::configuration::database::{
    DatabaseConfiguration, DatabaseConfigurationBuilder,
};
use crate::application::configuration::messaging::{
    EnvNames, MessagingConfiguration, MessagingConfigurationBuilder,
};
use dotenvy::{dotenv, from_filename};
use std::collections::HashMap;
use std::fmt::Debug;

pub struct ConfigurationBuilder {
    pub app: AppConfigurationBuilder,
    pub db: DatabaseConfigurationBuilder,
    pub publisher: MessagingConfigurationBuilder,
}

impl ConfigurationBuilder {
    pub fn new(
        app: AppConfigurationBuilder,
        db: DatabaseConfigurationBuilder,
        publisher: MessagingConfigurationBuilder,
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
    publisher: MessagingConfiguration,
}

impl Configuration {
    pub fn new(
        app: AppConfiguration,
        db: DatabaseConfiguration,
        publisher: MessagingConfiguration,
    ) -> Self {
        Configuration { app, db, publisher }
    }

    pub fn load<F>(loader: F) -> Self
    where
        F: FnOnce(
            AppConfigurationBuilder,
            DatabaseConfigurationBuilder,
            MessagingConfigurationBuilder,
        ) -> (
            AppConfiguration,
            DatabaseConfiguration,
            MessagingConfiguration,
        ),
    {
        let (app, db, publisher) = loader(
            AppConfigurationBuilder::new(),
            DatabaseConfigurationBuilder::new(),
            MessagingConfigurationBuilder::new(),
        );

        Configuration { app, db, publisher }
    }

    pub fn envs(&self) -> HashMap<String, String> {
        let mut envs = HashMap::new();
        envs.extend(self.app.envs());
        envs.extend(self.db.envs());
        match &self.publisher {
            MessagingConfiguration::Rabbitmq(config) => {
                envs.extend(config.envs());
                envs.insert(
                    EnvNames::MESSAGE_PUBLISHER_ENGINE.to_owned(),
                    "rabbitmq".to_owned(),
                );
            }
            MessagingConfiguration::None => {
                envs.insert(
                    EnvNames::MESSAGE_PUBLISHER_ENGINE.to_owned(),
                    "none".to_owned(),
                );
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

    pub fn messaging(&self) -> &MessagingConfiguration {
        &self.publisher
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration::load(|mut app, mut db, mut publisher| {
            from_filename(".env.local").or(dotenv()).ok();

            (
                app.load_env().build(),
                db.load_env().build(),
                publisher.load_env().build(),
            )
        })
    }
}
