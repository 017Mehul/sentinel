-- 000008_create_oauth_accounts.up.sql
-- OAuth2 provider account linking.
-- One user can have multiple providers linked.

CREATE TABLE oauth_accounts (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider          VARCHAR(50) NOT NULL,           -- "google", "github"
    provider_user_id  VARCHAR(255) NOT NULL,
    provider_email    VARCHAR(255),
    access_token_enc  TEXT,                           -- AES-256-GCM encrypted
    refresh_token_enc TEXT,                           -- AES-256-GCM encrypted
    token_expires_at  TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A user can link each provider at most once
CREATE UNIQUE INDEX idx_oauth_provider_user
    ON oauth_accounts(provider, provider_user_id);

-- Look up all providers linked to a user
CREATE INDEX idx_oauth_user_id ON oauth_accounts(user_id);
