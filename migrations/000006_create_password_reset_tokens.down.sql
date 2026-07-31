-- 000006_create_password_reset_tokens.down.sql
DROP INDEX IF EXISTS idx_prt_cleanup;
DROP INDEX IF EXISTS idx_prt_token_hash;
DROP TABLE IF EXISTS password_reset_tokens;
