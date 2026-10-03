-- +goose Up
-- Kubectl gateway (plan §7.2): seed the new clusters.kubectl catalog
-- permission into the built-in admin and operator roles of every existing
-- tenant (new tenants get it from authz.BuiltinRoles). OrgRoleSync converges
-- the FGA team#member → organization clusters_kubectl tuples from these
-- rows on its next pass.
UPDATE roles
SET permissions = permissions || '["clusters.kubectl"]'::jsonb,
    updated_at = now()
WHERE builtin
  AND name IN ('admin', 'operator')
  AND NOT permissions @> '["clusters.kubectl"]'::jsonb;

-- +goose Down
UPDATE roles
SET permissions = permissions - 'clusters.kubectl',
    updated_at = now()
WHERE builtin
  AND name IN ('admin', 'operator')
  AND permissions @> '["clusters.kubectl"]'::jsonb;
