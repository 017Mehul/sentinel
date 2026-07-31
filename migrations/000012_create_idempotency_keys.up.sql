-- 000012_create_idempotency_keys.up.sql
-- Database-layer idempotency storage (Redis is the fast-path; this is the durable record).

CREATE TABLE idempotency_keys (
    key        VARCHAR(255) PRIMARY KEY,
    user_id    UUID         REFERENCES users(id) ON DELETE SET NULL,
    method     VARCHAR(10)  NOT NULL,
    path       VARCHAR(255) NOT NULL,
    response   JSONB        NOT NULL,
    status_code INT         NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_idempotency_expires_at ON idempotency_keys(expires_at);
