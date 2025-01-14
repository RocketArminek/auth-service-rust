-- Add up migration script here
CREATE TABLE sessions (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL,
    access_token TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_access_token ON sessions(access_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
