-- Drop indexes first
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_created_at;
DROP INDEX IF EXISTS idx_user_roles_user_role;
DROP INDEX IF EXISTS idx_roles_name;

-- Drop tables in reverse order of creation (due to foreign key constraints)
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
