-- 001_create_users.up.sql
-- Core user identity table

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- provides gen_random_uuid()

CREATE TABLE users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL,
    password_hash   VARCHAR(255),               -- NULL for OAuth-only accounts
    full_name       VARCHAR(255) NOT NULL,
    avatar_url      TEXT,
    is_verified     BOOLEAN     NOT NULL DEFAULT FALSE,
    is_locked       BOOLEAN     NOT NULL DEFAULT FALSE,
    failed_attempts INT         NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ                 -- soft delete
);

-- Unique email constraint only on non-deleted rows
CREATE UNIQUE INDEX idx_users_email_unique
    ON users(email)
    WHERE deleted_at IS NULL;

-- Fast lookup for soft-deleted filter (most queries exclude deleted rows)
CREATE INDEX idx_users_email
    ON users(email)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_users_created_at
    ON users(created_at DESC)
    WHERE deleted_at IS NULL;
