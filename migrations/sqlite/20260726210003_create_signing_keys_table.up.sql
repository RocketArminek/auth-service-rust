CREATE TABLE signing_keys
(
    kid                TEXT     PRIMARY KEY,
    alg                TEXT     NOT NULL,
    public_key         TEXT     NOT NULL,
    sealed_private_key BLOB     NOT NULL,
    created_at         DATETIME NOT NULL,
    retired_at         DATETIME DEFAULT NULL
);

CREATE UNIQUE INDEX unique_active_signing_key ON signing_keys (retired_at IS NULL) WHERE retired_at IS NULL;
