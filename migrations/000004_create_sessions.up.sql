-- 000004_create_sessions.up.sql
-- Sessions: Redis is source-of-truth for active sessions.
-- Postgres stores session history for audit and admin queries.

CREATE TABLE sessions (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_id UUID        REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    device_info      JSONB,       -- {user_agent, os, browser, device_type}
    ip_address       INET,
    user_agent       TEXT,
    last_active_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ              -- soft delete = revoked
);

CREATE INDEX idx_sessions_user_id
    ON sessions(user_id)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_sessions_created_at
    ON sessions(created_at DESC);
