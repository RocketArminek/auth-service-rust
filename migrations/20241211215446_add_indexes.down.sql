-- Add down migration script here
DROP INDEX idx_users_email ON users;
DROP INDEX idx_users_created_at ON users;
DROP INDEX idx_user_roles_user_role ON user_roles;
DROP INDEX idx_roles_name ON roles;
