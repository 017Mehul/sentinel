-- 000005_create_login_history.up.sql
-- Immutable login attempt log — read model for CQRS pattern.
-- Rows are never updated or deleted (append-only).

CREATE TABLE login_history (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        REFERENCES users(id) ON DELETE SET NULL,
    email          VARCHAR(255),        -- denormalized for queries after user deletion
    ip_address     INET,
    user_agent     TEXT,
    success        BOOLEAN     NOT NULL,
    failure_reason VARCHAR(100),        -- e.g., "invalid_password", "account_locked"
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Admin and user queries: login history for a specific user, newest first
CREATE INDEX idx_lh_user_id_created_at
    ON login_history(user_id, created_at DESC);

-- Security analytics: failed logins from a specific IP
CREATE INDEX idx_lh_ip_created_at
    ON login_history(ip_address, created_at DESC)
    WHERE success = FALSE;
