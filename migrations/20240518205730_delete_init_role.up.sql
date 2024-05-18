-- Add up migration script here
DELETE FROM roles WHERE name = 'AUTH_OWNER';
