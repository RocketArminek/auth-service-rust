-- Add down migration script here
DROP INDEX idx_permissions_group;
DROP TABLE role_permissions;
DROP TABLE permissions;
