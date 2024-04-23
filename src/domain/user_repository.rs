use uuid::Uuid;
use crate::domain::error::{StorageError};
use crate::domain::user::User;

trait UserRepository {
    fn add(&self, user: &User) -> Result<(), StorageError>;
    fn get_by_id(&self, id: Uuid) -> Option<User>;
    fn get_by_email(&self, email: &String) -> Option<User>;
}
