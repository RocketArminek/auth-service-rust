-- Add up migration script here
CREATE TABLE permissions
(
    id          BLOB PRIMARY KEY,
    name        TEXT NOT NULL,
    group_name  TEXT NOT NULL,
    description TEXT,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  DATETIME NOT NULL,
    UNIQUE (name, group_name)
);

CREATE TABLE role_permissions
(
    role_id       BLOB NOT NULL,
    permission_id BLOB NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE INDEX idx_permissions_group ON permissions (group_name);
