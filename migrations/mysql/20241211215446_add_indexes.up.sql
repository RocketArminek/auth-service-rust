-- Add up migration script here
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at DESC);
CREATE INDEX idx_user_roles_user_role ON user_roles(user_id, role_id);
CREATE INDEX idx_roles_name ON roles(name);
