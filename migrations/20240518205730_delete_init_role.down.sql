-- Add down migration script here
INSERT INTO roles (id, name, created_at) VALUES
    (UNHEX(REPLACE('018f8b15-4759-787c-bc55-1b8337d0e45c', '-', '')), 'AUTH_OWNER', NOW());
