use crate::application::configuration::messaging::MessagingConfiguration;
use crate::infrastructure::rabbitmq_message_publisher::{
    RabbitmqMessagePublisher, create_rabbitmq_connection, create_rabbitmq_message_publisher,
};
use lapin::Error as LapinError;
use serde::Serialize;
use serde_json::Error as SerdeError;
use std::fmt::{Debug, Display};

#[derive(Debug)]
pub enum Error {
    Rabbitmq(LapinError),
    Serde(SerdeError),
    Unknown,
}

impl From<LapinError> for Error {
    fn from(value: LapinError) -> Self {
        Self::Rabbitmq(value)
    }
}

impl From<SerdeError> for Error {
    fn from(value: SerdeError) -> Self {
        Self::Serde(value)
    }
}

#[derive(Debug, Clone, Default)]
pub enum MessagingEngine {
    Rabbitmq,
    #[default]
    None,
}

impl Display for MessagingEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessagingEngine::None => write!(f, "none"),
            MessagingEngine::Rabbitmq => write!(f, "rabbitmq"),
        }
    }
}

impl From<MessagingEngine> for String {
    fn from(value: MessagingEngine) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for MessagingEngine {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "none" => Ok(MessagingEngine::None),
            "rabbitmq" => Ok(MessagingEngine::Rabbitmq),
            _ => Err(format!("Unknown message publisher type: {}", value)),
        }
    }
}

#[derive(Clone)]
pub enum MessagePublisher {
    None,
    Rabbitmq(RabbitmqMessagePublisher),
}

impl MessagePublisher {
    pub async fn new(config: &MessagingConfiguration) -> Self {
        match config {
            MessagingConfiguration::Rabbitmq(config) => {
                let conn = create_rabbitmq_connection(config).await;
                let publisher = create_rabbitmq_message_publisher(config, &conn).await;

                MessagePublisher::Rabbitmq(publisher)
            }
            MessagingConfiguration::None => MessagePublisher::None,
        }
    }

    pub async fn publish<T: Serialize>(&self, event: &T) -> Result<(), Error> {
        match &self {
            MessagePublisher::None => Ok(()),
            MessagePublisher::Rabbitmq(publisher) => publisher.publish(event).await,
        }
    }

    pub async fn publish_all<T: Serialize>(&self, events: Vec<&T>) -> Result<(), Error> {
        match &self {
            MessagePublisher::None => Ok(()),
            MessagePublisher::Rabbitmq(publisher) => publisher.publish_all(events).await,
        }
    }
}
