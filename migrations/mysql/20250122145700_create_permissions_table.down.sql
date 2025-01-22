-- Add down migration script here
DROP INDEX idx_permissions_group ON permissions;
DROP TABLE role_permissions;
DROP TABLE permissions;
