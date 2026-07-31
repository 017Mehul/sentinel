-- 000003_create_refresh_tokens.down.sql
DROP INDEX IF EXISTS idx_rt_cleanup;
DROP INDEX IF EXISTS idx_rt_user_id;
DROP INDEX IF EXISTS idx_rt_family_id;
DROP INDEX IF EXISTS idx_rt_token_hash;
DROP TABLE IF EXISTS refresh_tokens;
