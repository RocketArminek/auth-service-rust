CREATE TABLE signing_keys
(
    kid                VARCHAR(64)  PRIMARY KEY,
    alg                VARCHAR(16)  NOT NULL,
    public_key         VARCHAR(255) NOT NULL,
    sealed_private_key VARBINARY(512) NOT NULL,
    created_at         DATETIME     NOT NULL,
    retired_at         DATETIME     DEFAULT NULL,
    is_active          TINYINT GENERATED ALWAYS AS (IF(retired_at IS NULL, 1, NULL)) STORED,
    UNIQUE KEY unique_active_signing_key (is_active)
);
