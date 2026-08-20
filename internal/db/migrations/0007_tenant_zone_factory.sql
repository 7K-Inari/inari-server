-- +goose Up
-- Tenant Zone Factory (plan §5.12): vended tenant zones and their
-- resumable provisioning/decommission steps. Long-running AWS operations
-- persist their handle in tenant_zone_steps.external_ref so restarts
-- resume polling instead of re-creating (§10 zombie-zone mitigation).
CREATE TABLE tenant_zones (
    id                    TEXT PRIMARY KEY,
    slug                  TEXT NOT NULL UNIQUE,
    display_name          TEXT NOT NULL,
    owner_org_id          TEXT NOT NULL, -- org owning the management account (platform org)
    org_id                TEXT NOT NULL DEFAULT '', -- wired Keycloak org; empty until inari_wiring
    ou_id                 TEXT NOT NULL,
    region                TEXT NOT NULL,
    tier                  TEXT NOT NULL DEFAULT 'starter',
    state                 TEXT NOT NULL DEFAULT 'requested',
    management_account_id TEXT NOT NULL REFERENCES cloud_accounts(id),
    aws_account_id        TEXT NOT NULL DEFAULT '',
    cluster_id            TEXT NOT NULL DEFAULT '',
    cloud_account_id      TEXT NOT NULL DEFAULT '',
    keycloak_org_id       TEXT NOT NULL DEFAULT '',
    git_repo              TEXT NOT NULL DEFAULT '',
    tags                  JSONB NOT NULL DEFAULT '{}',
    error                 TEXT NOT NULL DEFAULT '',
    created_by            TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tenant_zone_steps (
    zone_id      TEXT NOT NULL REFERENCES tenant_zones(id) ON DELETE CASCADE,
    step         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|running|waiting|succeeded|failed|skipped
    external_ref TEXT NOT NULL DEFAULT '',
    detail       JSONB NOT NULL DEFAULT '{}',
    attempts     INT NOT NULL DEFAULT 0,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (zone_id, step)
);

CREATE INDEX tenant_zones_state_idx ON tenant_zones (state);
CREATE INDEX tenant_zones_owner_org_idx ON tenant_zones (owner_org_id);

-- +goose Down
DROP TABLE IF EXISTS tenant_zone_steps;
DROP TABLE IF EXISTS tenant_zones;
