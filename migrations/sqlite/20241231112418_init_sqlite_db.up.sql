-- Create users table
CREATE TABLE IF NOT EXISTS users
(
    id          BLOB PRIMARY KEY,
    email       TEXT     NOT NULL UNIQUE,
    password    TEXT     NOT NULL,
    created_at  DATETIME NOT NULL,
    first_name  TEXT,
    last_name   TEXT,
    avatar_path TEXT,
    is_verified BOOLEAN DEFAULT FALSE
);

-- Create roles table
CREATE TABLE IF NOT EXISTS roles
(
    id         BLOB PRIMARY KEY,
    name       TEXT     NOT NULL UNIQUE,
    created_at DATETIME NOT NULL
);

-- Create user_roles table
CREATE TABLE IF NOT EXISTS user_roles
(
    user_id BLOB NOT NULL,
    role_id BLOB NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_created_at ON users (created_at DESC);
CREATE INDEX idx_user_roles_user_role ON user_roles (user_id, role_id);
CREATE INDEX idx_roles_name ON roles (name);
