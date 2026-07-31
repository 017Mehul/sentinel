-- 000014_seed_rbac.up.sql
-- Seed default roles and permissions.
-- Permissions follow the pattern: resource.action

-- Default roles
INSERT INTO roles (id, name, description) VALUES
    (gen_random_uuid(), 'admin',  'Full system access'),
    (gen_random_uuid(), 'user',   'Standard authenticated user'),
    (gen_random_uuid(), 'moderator', 'Content moderation access');

-- System permissions
INSERT INTO permissions (id, name, resource, action, description) VALUES
    -- Users
    (gen_random_uuid(), 'users.read',   'users', 'read',   'View user profiles'),
    (gen_random_uuid(), 'users.write',  'users', 'write',  'Create or update users'),
    (gen_random_uuid(), 'users.delete', 'users', 'delete', 'Delete users'),
    (gen_random_uuid(), 'users.lock',   'users', 'lock',   'Lock or unlock user accounts'),

    -- Admin dashboard
    (gen_random_uuid(), 'admin.dashboard', 'admin', 'dashboard', 'Access admin dashboard'),
    (gen_random_uuid(), 'admin.audit',     'admin', 'audit',     'View audit logs'),
    (gen_random_uuid(), 'admin.sessions',  'admin', 'sessions',  'Manage all sessions'),

    -- RBAC management
    (gen_random_uuid(), 'roles.read',   'roles', 'read',   'View roles'),
    (gen_random_uuid(), 'roles.write',  'roles', 'write',  'Create or update roles'),
    (gen_random_uuid(), 'roles.delete', 'roles', 'delete', 'Delete roles'),
    (gen_random_uuid(), 'roles.assign', 'roles', 'assign', 'Assign roles to users'),

    -- Billing (example future permission)
    (gen_random_uuid(), 'billing.manage', 'billing', 'manage', 'Manage billing and subscriptions');

-- Assign all permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    id
FROM permissions;

-- Assign basic permissions to user role
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    (SELECT id FROM roles WHERE name = 'user'),
    id
FROM permissions
WHERE name IN ('users.read');
