use crate::domain::crypto::HashingScheme;
use crate::infrastructure::mysql_user_repository::MysqlUserRepository;

pub mod routes;
pub mod user_controller;
pub mod utils_controller;

#[derive(Clone)]
pub struct ServerState {
    pub secret: String,
    pub hashing_scheme: HashingScheme,
    pub repository: MysqlUserRepository,
}
