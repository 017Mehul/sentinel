-- 000007_create_email_verification_tokens.down.sql
DROP INDEX IF EXISTS idx_evt_cleanup;
DROP INDEX IF EXISTS idx_evt_user_id;
DROP INDEX IF EXISTS idx_evt_token_hash;
DROP TABLE IF EXISTS email_verification_tokens;
