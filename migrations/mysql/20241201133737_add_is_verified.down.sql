-- Add down migration script here
ALTER TABLE users DROP COLUMN is_verified;
