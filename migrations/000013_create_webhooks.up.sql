-- 000013_create_webhooks.up.sql
-- Webhook endpoint registration and delivery log.

CREATE TABLE webhook_endpoints (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url        TEXT        NOT NULL,
    secret     VARCHAR(255) NOT NULL,   -- HMAC-SHA256 signing secret (stored hashed)
    events     TEXT[]      NOT NULL,    -- subscribed event types
    is_active  BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_we_user_id ON webhook_endpoints(user_id) WHERE is_active = TRUE;

CREATE TABLE webhook_deliveries (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id         UUID        NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type          VARCHAR(100) NOT NULL,
    payload             JSONB       NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    http_status         INT,
    response_body       TEXT,
    attempts            INT         NOT NULL DEFAULT 0,
    next_retry_at       TIMESTAMPTZ,
    delivered_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_wd_endpoint_id ON webhook_deliveries(endpoint_id, created_at DESC);

CREATE INDEX idx_wd_retry
    ON webhook_deliveries(next_retry_at ASC)
    WHERE status IN ('pending', 'failed') AND attempts < 5;
