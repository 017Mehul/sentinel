-- 000009_create_audit_logs.down.sql
DROP INDEX IF EXISTS idx_audit_created_at;
DROP INDEX IF EXISTS idx_audit_action_created_at;
DROP INDEX IF EXISTS idx_audit_user_id_created_at;
DROP TABLE IF EXISTS audit_logs;
