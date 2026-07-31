-- 000011_create_outbox_events.up.sql
-- Transactional Outbox pattern: events are written atomically with the
-- business transaction and delivered asynchronously by the OutboxWorker.

CREATE TABLE outbox_events (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type   VARCHAR(100) NOT NULL,  -- e.g., "auth.user.registered"
    payload      JSONB       NOT NULL,
    status       VARCHAR(20) NOT NULL DEFAULT 'pending',
                                         -- pending | processing | sent | failed
    attempts     INT         NOT NULL DEFAULT 0,
    last_error   TEXT,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- for delayed delivery
    processed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Worker query: poll pending events ordered by scheduled_at.
-- Partial index only on pending rows keeps the index small.
CREATE INDEX idx_outbox_pending
    ON outbox_events(scheduled_at ASC)
    WHERE status = 'pending';

-- Retry worker: failed events with remaining attempts
CREATE INDEX idx_outbox_retry
    ON outbox_events(scheduled_at ASC)
    WHERE status = 'failed' AND attempts < 5;
