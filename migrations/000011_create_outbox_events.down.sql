-- 000011_create_outbox_events.down.sql
DROP INDEX IF EXISTS idx_outbox_retry;
DROP INDEX IF EXISTS idx_outbox_pending;
DROP TABLE IF EXISTS outbox_events;
