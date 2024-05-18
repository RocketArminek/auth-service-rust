-- Add up migration script here
CREATE TABLE roles (
    id BINARY(16) PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    created_at DATETIME NOT NULL
);

CREATE TABLE user_roles (
    user_id BINARY(16) NOT NULL,
    role_id BINARY(16) NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);
