-- Add down migration script here
ALTER TABLE roles DROP COLUMN is_system;
