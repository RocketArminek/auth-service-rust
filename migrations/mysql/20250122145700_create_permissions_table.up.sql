-- Add up migration script here
CREATE TABLE permissions
(
    id          BINARY(16) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    group_name  VARCHAR(255) NOT NULL,
    description TEXT,
    created_at  DATETIME     NOT NULL,
    UNIQUE KEY unique_permission_name (name, group_name)
);

CREATE TABLE role_permissions
(
    role_id       BINARY(16) NOT NULL,
    permission_id BINARY(16) NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE INDEX idx_permissions_group ON permissions (group_name);
