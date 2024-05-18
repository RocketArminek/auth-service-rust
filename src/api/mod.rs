use std::sync::Arc;
use tokio::sync::Mutex;
use crate::domain::crypto::HashingScheme;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;

pub mod routes;
mod token_extractor;
pub mod user_controller;
pub mod utils_controller;
pub mod dto;
pub mod stateless_auth_controller;

#[derive(Clone)]
pub struct ServerState {
    pub secret: String,
    pub hashing_scheme: HashingScheme,
    pub repository: Arc<Mutex<MysqlUserRepository>>,
}
