-- 000008_create_oauth_accounts.down.sql
DROP INDEX IF EXISTS idx_oauth_user_id;
DROP INDEX IF EXISTS idx_oauth_provider_user;
DROP TABLE IF EXISTS oauth_accounts;
