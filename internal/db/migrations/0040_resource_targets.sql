-- +goose Up
-- Org resource targets are authorization/configuration overlays over the
-- existing inventory. They do not duplicate clusters, repos, or addons.
CREATE TABLE resource_targets (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    capability    TEXT NOT NULL,
    config        JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(config) = 'object'),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    is_default    BOOLEAN NOT NULL DEFAULT FALSE,
    revision      BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, capability, resource_kind, resource_id),
    UNIQUE (org_id, capability, name)
);

CREATE INDEX resource_targets_org_idx ON resource_targets (org_id);
CREATE INDEX resource_targets_resource_idx ON resource_targets (resource_kind, resource_id);
CREATE UNIQUE INDEX resource_targets_one_default
    ON resource_targets (org_id, capability) WHERE is_default;

CREATE TABLE resource_target_grants (
    target_id  TEXT NOT NULL REFERENCES resource_targets(id) ON DELETE CASCADE,
    team_id    UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    relation   TEXT NOT NULL CHECK (relation IN ('view', 'use', 'provision')),
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (target_id, team_id)
);

CREATE INDEX resource_target_grants_team_idx ON resource_target_grants (team_id);

-- Preserve existing deployment access. The target ID is deterministic so a
-- migration retry cannot duplicate an overlay. Revoked/decommissioned
-- clusters have no deployable target; pending clusters backfill as disabled
-- by provider readiness until they become active.
INSERT INTO resource_targets
    (id, org_id, name, resource_kind, resource_id, capability, created_by)
SELECT 'rt-' || substr(md5(c.org_id || ':' || c.id || ':deployment.cluster'), 1, 26),
       c.org_id, c.name, 'cluster', c.id, 'deployment.cluster', 'migration:0040'
FROM clusters c
WHERE c.state NOT IN ('revoked', 'decommissioned');

INSERT INTO resource_target_grants (target_id, team_id, relation, created_by)
SELECT rt.id, t.id,
       CASE WHEN r.permissions ? 'deployments.create' THEN 'use' ELSE 'view' END,
       'migration:0040'
FROM resource_targets rt
JOIN teams t ON t.org_id = rt.org_id
JOIN roles r ON r.id = t.role_id
WHERE rt.capability = 'deployment.cluster'
  AND (r.permissions ? 'tenant.read' OR r.permissions ? 'deployments.create');

UPDATE roles
SET permissions = permissions || '["resourcetargets.manage"]'::jsonb, updated_at = now()
WHERE builtin AND name IN ('admin', 'operator')
  AND NOT permissions ? 'resourcetargets.manage';

-- +goose Down
UPDATE roles
SET permissions = permissions - 'resourcetargets.manage', updated_at = now()
WHERE builtin AND name IN ('admin', 'operator');
DROP TABLE IF EXISTS resource_target_grants;
DROP TABLE IF EXISTS resource_targets;
