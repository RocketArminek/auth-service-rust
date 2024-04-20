-- Add up migration script here
CREATE TABLE users (
   id BINARY(16) PRIMARY KEY,
   email VARCHAR(255) NOT NULL UNIQUE,
   password VARCHAR(255) NOT NULL,
   created_at DATETIME NOT NULL
);
