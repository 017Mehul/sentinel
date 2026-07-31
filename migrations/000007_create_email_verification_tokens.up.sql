-- 000007_create_email_verification_tokens.up.sql

CREATE TABLE email_verification_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_evt_token_hash ON email_verification_tokens(token_hash);

CREATE INDEX idx_evt_user_id ON email_verification_tokens(user_id);

-- Cleanup index
CREATE INDEX idx_evt_cleanup
    ON email_verification_tokens(expires_at)
    WHERE used_at IS NULL;
