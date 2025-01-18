-- Add up migration script here
ALTER TABLE roles ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT FALSE;
