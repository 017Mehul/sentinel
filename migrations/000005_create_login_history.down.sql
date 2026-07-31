-- 000005_create_login_history.down.sql
DROP INDEX IF EXISTS idx_lh_ip_created_at;
DROP INDEX IF EXISTS idx_lh_user_id_created_at;
DROP TABLE IF EXISTS login_history;
