use crate::infrastructure::message_publisher::MessagingEngine;
use lapin::ExchangeKind;
use lapin::options::ExchangeDeclareOptions;
use std::collections::HashMap;
use std::env;

pub struct MessagingConfigurationBuilder {
    pub engine: Option<MessagingEngine>,
    pub rabbitmq_url: Option<String>,
    pub rabbitmq_exchange_name: Option<String>,
    pub rabbitmq_exchange_kind: Option<ExchangeKind>,
    pub rabbitmq_exchange_durable: Option<bool>,
    pub rabbitmq_exchange_auto_delete: Option<bool>,
}

impl Default for MessagingConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagingConfigurationBuilder {
    pub fn new() -> Self {
        MessagingConfigurationBuilder {
            engine: None,
            rabbitmq_url: None,
            rabbitmq_exchange_name: None,
            rabbitmq_exchange_kind: None,
            rabbitmq_exchange_durable: None,
            rabbitmq_exchange_auto_delete: None,
        }
    }

    pub fn engine(&mut self, value: MessagingEngine) -> &mut Self {
        self.engine = Some(value);
        self
    }

    pub fn rabbitmq_url(&mut self, value: String) -> &mut Self {
        self.rabbitmq_url = Some(value);
        self
    }

    pub fn rabbitmq_exchange_name(&mut self, value: String) -> &mut Self {
        self.rabbitmq_exchange_name = Some(value);
        self
    }

    pub fn rabbitmq_exchange_kind(&mut self, value: ExchangeKind) -> &mut Self {
        self.rabbitmq_exchange_kind = Some(value);
        self
    }

    pub fn rabbitmq_exchange_durable(&mut self, value: bool) -> &mut Self {
        self.rabbitmq_exchange_durable = Some(value);
        self
    }

    pub fn rabbitmq_exchange_auto_delete(&mut self, value: bool) -> &mut Self {
        self.rabbitmq_exchange_auto_delete = Some(value);
        self
    }

    pub fn load_env(&mut self) -> &mut Self {
        self.engine = env::var(EnvNames::MESSAGE_PUBLISHER_ENGINE)
            .map(|v| v.try_into().unwrap_or_default())
            .ok();

        self.rabbitmq_url = env::var(EnvNames::RABBITMQ_URL).ok();
        self.rabbitmq_exchange_name = env::var(EnvNames::RABBITMQ_EXCHANGE_NAME).ok();
        self.rabbitmq_exchange_kind = env::var(EnvNames::RABBITMQ_EXCHANGE_KIND)
            .map(Self::exchange_kind_from_string)
            .ok();
        self.rabbitmq_exchange_durable = env::var(EnvNames::RABBITMQ_EXCHANGE_DURABLE)
            .map(|v| v.parse::<bool>().unwrap())
            .ok();
        self.rabbitmq_exchange_auto_delete = env::var(EnvNames::RABBITMQ_EXCHANGE_AUTO_DELETE)
            .map(|v| v.parse::<bool>().unwrap())
            .ok();

        self
    }

    pub fn build(&self) -> MessagingConfiguration {
        match self.engine {
            Some(MessagingEngine::Rabbitmq) => {
                let rabbitmq_exchange_declare_options = ExchangeDeclareOptions {
                    auto_delete: self.rabbitmq_exchange_auto_delete.unwrap_or_default(),
                    durable: self.rabbitmq_exchange_durable.unwrap_or_default(),
                    ..ExchangeDeclareOptions::default()
                };

                MessagingConfiguration::Rabbitmq(RabbitmqConfiguration::new(
                    self.rabbitmq_url
                        .clone()
                        .unwrap_or("amqp://localhost:5672".to_string()),
                    self.rabbitmq_exchange_name
                        .clone()
                        .unwrap_or("auth.events".to_string()),
                    self.rabbitmq_exchange_kind
                        .clone()
                        .unwrap_or(ExchangeKind::Fanout),
                    rabbitmq_exchange_declare_options,
                ))
            }
            Some(MessagingEngine::None) => MessagingConfiguration::None,
            None => MessagingConfiguration::None,
        }
    }

    fn exchange_kind_from_string(value: String) -> ExchangeKind {
        match value.as_str() {
            "direct" => ExchangeKind::Direct,
            "fanout" => ExchangeKind::Fanout,
            "headers" => ExchangeKind::Headers,
            "topic" => ExchangeKind::Topic,
            _ => panic!("Unknown exchange kind"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MessagingConfiguration {
    Rabbitmq(RabbitmqConfiguration),
    None,
}

#[derive(Debug, Clone)]
pub struct RabbitmqConfiguration {
    rabbitmq_url: String,
    rabbitmq_exchange_name: String,
    rabbitmq_exchange_kind: ExchangeKind,
    rabbitmq_exchange_declare_options: ExchangeDeclareOptions,
}

impl RabbitmqConfiguration {
    pub fn new(
        rabbitmq_url: String,
        rabbitmq_exchange_name: String,
        rabbitmq_exchange_kind: ExchangeKind,
        rabbitmq_exchange_declare_options: ExchangeDeclareOptions,
    ) -> Self {
        RabbitmqConfiguration {
            rabbitmq_url,
            rabbitmq_exchange_name,
            rabbitmq_exchange_kind,
            rabbitmq_exchange_declare_options,
        }
    }

    pub fn rabbitmq_exchange_name(&self) -> &str {
        &self.rabbitmq_exchange_name
    }

    pub fn rabbitmq_url(&self) -> &str {
        &self.rabbitmq_url
    }

    pub fn rabbitmq_exchange_kind(&self) -> &ExchangeKind {
        &self.rabbitmq_exchange_kind
    }

    pub fn rabbitmq_exchange_declare_options(&self) -> ExchangeDeclareOptions {
        self.rabbitmq_exchange_declare_options
    }

    pub fn envs(&self) -> HashMap<String, String> {
        let mut envs = HashMap::new();

        envs.insert(EnvNames::RABBITMQ_URL.to_owned(), self.rabbitmq_url.clone());
        envs.insert(
            EnvNames::RABBITMQ_EXCHANGE_NAME.to_owned(),
            self.rabbitmq_exchange_name.clone(),
        );
        envs.insert(
            EnvNames::RABBITMQ_EXCHANGE_KIND.to_owned(),
            Self::exchange_kind_to_string(self.rabbitmq_exchange_kind.clone()),
        );

        envs.insert(
            EnvNames::RABBITMQ_EXCHANGE_DURABLE.to_owned(),
            self.rabbitmq_exchange_declare_options.durable.to_string(),
        );
        envs.insert(
            EnvNames::RABBITMQ_EXCHANGE_AUTO_DELETE.to_owned(),
            self.rabbitmq_exchange_declare_options
                .auto_delete
                .to_string(),
        );

        envs
    }

    fn exchange_kind_to_string(value: ExchangeKind) -> String {
        match value {
            ExchangeKind::Custom(_) => "custom".to_string(),
            ExchangeKind::Direct => "direct".to_string(),
            ExchangeKind::Fanout => "fanout".to_string(),
            ExchangeKind::Headers => "headers".to_string(),
            ExchangeKind::Topic => "topic".to_string(),
        }
    }
}

pub struct EnvNames;

impl EnvNames {
    pub const MESSAGE_PUBLISHER_ENGINE: &'static str = "MESSAGE_PUBLISHER_ENGINE";
    pub const RABBITMQ_URL: &'static str = "RABBITMQ_URL";
    pub const RABBITMQ_EXCHANGE_NAME: &'static str = "RABBITMQ_EXCHANGE_NAME";
    pub const RABBITMQ_EXCHANGE_KIND: &'static str = "RABBITMQ_EXCHANGE_KIND";
    pub const RABBITMQ_EXCHANGE_DURABLE: &'static str = "RABBITMQ_EXCHANGE_DURABLE";
    pub const RABBITMQ_EXCHANGE_AUTO_DELETE: &'static str = "RABBITMQ_EXCHANGE_AUTO_DELETE";
}
