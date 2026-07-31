-- 000002_create_roles_permissions.down.sql
DROP INDEX IF EXISTS idx_user_roles_role_id;
DROP INDEX IF EXISTS idx_user_roles_user_id;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP INDEX IF EXISTS idx_permissions_resource_action;
DROP INDEX IF EXISTS idx_permissions_name;
DROP TABLE IF EXISTS permissions;
DROP INDEX IF EXISTS idx_roles_name;
DROP TABLE IF EXISTS roles;
