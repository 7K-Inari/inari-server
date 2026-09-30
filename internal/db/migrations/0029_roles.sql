-- +goose Up
-- Role engine (ADR-0013): org-scoped, admin-customizable roles backed by the
-- static permission catalog. The 4 fixed hierarchical org roles
-- (membership_role enum) become seeded, deletion-protected built-in role
-- rows; teams and memberships reference roles by FK.

CREATE TABLE roles (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    builtin      BOOLEAN NOT NULL DEFAULT false,
    permissions  JSONB NOT NULL DEFAULT '[]',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- Seed the four built-in roles for every existing organization. Permission
-- bundles mirror the retired hierarchy (org-admin ⊇ platform-engineer ⊇
-- developer ⊇ viewer); keep in sync with authz.BuiltinRoles.
INSERT INTO roles (org_id, name, display_name, description, builtin, permissions)
SELECT o.id, b.name, b.display_name, b.description, true, b.permissions::jsonb
FROM organizations o
CROSS JOIN (VALUES
    ('admin', 'Org Admin', 'Full tenant administration',
     '["tenant.read","tenant.settings.write","tenant.members.manage","tenant.teams.manage","tenant.rbac.manage","tenant.identity.manage","tenant.notifications.manage","tenant.admin","clusters.register","cloudaccounts.manage","zones.manage","fleet.manage","policies.manage","secretstores.manage","extensions.manage","extensions.invoke","catalog.manage","deployments.create","approvals.manage"]'),
    ('operator', 'Platform Engineer', 'Operate the tenant''s clusters, infrastructure, and workloads',
     '["tenant.read","tenant.members.manage","clusters.register","cloudaccounts.manage","zones.manage","fleet.manage","policies.manage","secretstores.manage","extensions.manage","extensions.invoke","catalog.manage","deployments.create","approvals.manage"]'),
    ('editor', 'Developer', 'Deploy and manage workloads',
     '["tenant.read","catalog.manage","deployments.create","extensions.invoke","approvals.manage"]'),
    ('viewer', 'Viewer', 'Read-only access',
     '["tenant.read"]')
) AS b(name, display_name, description, permissions);

-- teams.role (enum) → teams.role_id FK, backfilled from the built-ins.
ALTER TABLE teams ADD COLUMN role_id UUID REFERENCES roles(id);

UPDATE teams t SET role_id = r.id FROM roles r
WHERE r.org_id = t.org_id AND r.name = CASE t.role
    WHEN 'org-admin' THEN 'admin'
    WHEN 'platform-engineer' THEN 'operator'
    WHEN 'developer' THEN 'editor'
    WHEN 'viewer' THEN 'viewer'
END;

ALTER TABLE teams ALTER COLUMN role_id SET NOT NULL;
ALTER TABLE teams DROP COLUMN role;

-- memberships.role (enum, part of the PK) → role_id FK.
ALTER TABLE memberships ADD COLUMN role_id UUID REFERENCES roles(id);

UPDATE memberships m SET role_id = r.id FROM roles r
WHERE r.org_id = m.org_id AND r.name = CASE m.role
    WHEN 'org-admin' THEN 'admin'
    WHEN 'platform-engineer' THEN 'operator'
    WHEN 'developer' THEN 'editor'
    WHEN 'viewer' THEN 'viewer'
END;

ALTER TABLE memberships ALTER COLUMN role_id SET NOT NULL;
ALTER TABLE memberships DROP CONSTRAINT memberships_pkey;
ALTER TABLE memberships DROP COLUMN role;
ALTER TABLE memberships ADD PRIMARY KEY (user_id, org_id, role_id);

DROP TYPE membership_role;

-- +goose Down
-- Best-effort restore of the fixed 4-role model. Custom roles and the
-- memberships bound to them have no enum representation and collapse to
-- 'viewer' (acknowledged data loss; pre-V1 clean swap, ADR-0013).
CREATE TYPE membership_role AS ENUM ('org-admin', 'platform-engineer', 'developer', 'viewer');

ALTER TABLE memberships ADD COLUMN role membership_role;
UPDATE memberships m SET role = CASE r.name
    WHEN 'admin' THEN 'org-admin'
    WHEN 'operator' THEN 'platform-engineer'
    WHEN 'editor' THEN 'developer'
    ELSE 'viewer'
END FROM roles r WHERE r.id = m.role_id;
ALTER TABLE memberships ALTER COLUMN role SET NOT NULL;
ALTER TABLE memberships DROP CONSTRAINT memberships_pkey;
ALTER TABLE memberships DROP COLUMN role_id;
ALTER TABLE memberships ADD PRIMARY KEY (user_id, org_id, role);

ALTER TABLE teams ADD COLUMN role membership_role NOT NULL DEFAULT 'viewer';
UPDATE teams t SET role = CASE r.name
    WHEN 'admin' THEN 'org-admin'
    WHEN 'operator' THEN 'platform-engineer'
    WHEN 'editor' THEN 'developer'
    ELSE 'viewer'
END FROM roles r WHERE r.id = t.role_id;
ALTER TABLE teams DROP COLUMN role_id;

DROP TABLE roles;
