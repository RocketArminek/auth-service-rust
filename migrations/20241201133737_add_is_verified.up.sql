-- Add up migration script here
ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;
