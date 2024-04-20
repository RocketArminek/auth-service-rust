use async_trait::async_trait;
use uuid::Uuid;
use crate::domain::error::Error;
use crate::domain::user::User;

#[async_trait]
pub trait Repository<T, I, E> {
    async fn add(&self, user: &T) -> Result<(), E>;
    async fn update(&self, user: &T) -> Result<(), E>;
    async fn delete(&self, user: &T) -> Result<(), E>;
    async fn get_by_id(&self, id: &I) -> Result<T, E>;
}

#[async_trait]
pub trait UserRepository: Repository<User, Uuid, Error> {
    async fn get_by_email(&self, email: &String) -> Result<User, Error>;
}
