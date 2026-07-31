-- 000013_create_webhooks.down.sql
DROP INDEX IF EXISTS idx_wd_retry;
DROP INDEX IF EXISTS idx_wd_endpoint_id;
DROP TABLE IF EXISTS webhook_deliveries;
DROP INDEX IF EXISTS idx_we_user_id;
DROP TABLE IF EXISTS webhook_endpoints;
