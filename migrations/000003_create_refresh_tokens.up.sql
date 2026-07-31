-- 000003_create_refresh_tokens.up.sql
-- Refresh token store with family-based rotation attack detection

CREATE TABLE refresh_tokens (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL,    -- SHA-256 hex of raw token (never store plaintext)
    family_id   UUID        NOT NULL,    -- All tokens in one rotation chain share a family_id
    device_info JSONB,                   -- {user_agent, os, browser, ip}
    ip_address  INET,
    revoked_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lookup by hash (used on every /refresh request)
CREATE UNIQUE INDEX idx_rt_token_hash ON refresh_tokens(token_hash);

-- Lookup all tokens in a family (used for rotation attack detection)
CREATE INDEX idx_rt_family_id ON refresh_tokens(family_id);

-- Lookup all tokens for a user (used for logout-all)
CREATE INDEX idx_rt_user_id ON refresh_tokens(user_id);

-- Composite index for cleanup worker: expired + not revoked
CREATE INDEX idx_rt_cleanup ON refresh_tokens(expires_at, revoked_at)
    WHERE revoked_at IS NULL;
