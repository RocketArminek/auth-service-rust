-- Add up migration script here
ALTER TABLE users ADD COLUMN avatar_path VARCHAR(255) DEFAULT NULL;
