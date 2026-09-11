-- +goose Up
-- M7 Platform resources (plan §5.2): control-plane-owned per-tenant platform
-- objects (keycloak realm/client, dns-zone, tenant namespace). Desired state
-- is written by the tenancy/zone-factory flow; status is reported back by the
-- platform reconciler. No tenant credentials are stored here.

CREATE TABLE platform_resources (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('keycloak-realm', 'keycloak-client', 'dns-zone', 'tenant-namespace')),
    name        TEXT NOT NULL,
    desired     JSONB NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'reconciling' CHECK (status IN ('ready', 'reconciling', 'failed')),
    detail      TEXT NOT NULL DEFAULT '',
    reported_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, kind, name)
);

CREATE INDEX platform_resources_org_idx ON platform_resources (org_id);

-- +goose Down
DROP TABLE IF EXISTS platform_resources;
