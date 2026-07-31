-- 000010_create_mfa.down.sql
DROP INDEX IF EXISTS idx_bc_user_unused;
DROP INDEX IF EXISTS idx_bc_user_id;
DROP TABLE IF EXISTS backup_codes;
DROP INDEX IF EXISTS idx_mfa_user_id;
DROP TABLE IF EXISTS mfa_secrets;
