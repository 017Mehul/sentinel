-- 000006_create_password_reset_tokens.up.sql

CREATE TABLE password_reset_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,   -- SHA-256 hex
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,            -- NULL = not yet used
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookup by token hash (called on every reset attempt)
CREATE UNIQUE INDEX idx_prt_token_hash ON password_reset_tokens(token_hash);

-- Cleanup worker: find expired unused tokens
CREATE INDEX idx_prt_cleanup
    ON password_reset_tokens(expires_at)
    WHERE used_at IS NULL;
