-- 000010_create_mfa.up.sql
-- TOTP secrets and backup codes for multi-factor authentication

CREATE TABLE mfa_secrets (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    secret_enc TEXT        NOT NULL,    -- AES-256-GCM encrypted TOTP secret
    is_enabled BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_user_id ON mfa_secrets(user_id);

CREATE TABLE backup_codes (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  VARCHAR(64) NOT NULL,    -- SHA-256 hex
    used_at    TIMESTAMPTZ,             -- NULL = available
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bc_user_id ON backup_codes(user_id);

-- Fast lookup of unused codes for a user
CREATE INDEX idx_bc_user_unused
    ON backup_codes(user_id)
    WHERE used_at IS NULL;
