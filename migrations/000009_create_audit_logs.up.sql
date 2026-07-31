-- 000009_create_audit_logs.up.sql
-- Immutable audit log — append-only, never updated or deleted.
-- CQRS write model; read queries use the query_repo with covering indexes.

CREATE TABLE audit_logs (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        REFERENCES users(id) ON DELETE SET NULL,
    actor_id   UUID        REFERENCES users(id) ON DELETE SET NULL, -- who performed the action (may differ from user_id in admin ops)
    action     VARCHAR(100) NOT NULL,   -- e.g., "auth.login", "rbac.role_assigned"
    resource   VARCHAR(100),            -- e.g., "user", "role"
    resource_id VARCHAR(255),           -- ID of the affected resource
    metadata   JSONB,                   -- additional context (old/new values, reason, etc.)
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Primary read pattern: all events for a user
CREATE INDEX idx_audit_user_id_created_at
    ON audit_logs(user_id, created_at DESC);

-- Admin dashboard: filter by action type + time range
CREATE INDEX idx_audit_action_created_at
    ON audit_logs(action, created_at DESC);

-- Retention worker: delete old entries
CREATE INDEX idx_audit_created_at ON audit_logs(created_at);
