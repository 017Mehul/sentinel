-- 000001_create_users.down.sql
DROP INDEX IF EXISTS idx_users_created_at;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_email_unique;
DROP TABLE IF EXISTS users;
