-- +goose Up
CREATE TYPE catalog_source AS ENUM ('discovered', 'curated', 'platform');
CREATE TYPE approval_policy AS ENUM ('auto', 'peer', 'platform-admin');

CREATE TABLE catalog_items (
    id              TEXT PRIMARY KEY,
    source          catalog_source NOT NULL,
    name            TEXT NOT NULL,
    display_name    TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    capability_ref  JSONB,
    oci_ref         TEXT NOT NULL DEFAULT '',
    approval_policy approval_policy NOT NULL DEFAULT 'auto',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE catalog_item_versions (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id  TEXT NOT NULL REFERENCES catalog_items(id) ON DELETE CASCADE,
    version  TEXT NOT NULL,
    channel  TEXT NOT NULL DEFAULT 'stable',
    schema   JSONB,
    ui_hints JSONB,
    payload  JSONB,
    UNIQUE (item_id, version)
);

CREATE TABLE catalog_visibility (
    item_id    TEXT NOT NULL REFERENCES catalog_items(id) ON DELETE CASCADE,
    org_id     TEXT NOT NULL,
    cluster_id TEXT NOT NULL DEFAULT '*',
    PRIMARY KEY (item_id, org_id, cluster_id)
);

CREATE TABLE catalog_pins (
    org_id  TEXT NOT NULL,
    item_id TEXT NOT NULL REFERENCES catalog_items(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    PRIMARY KEY (org_id, item_id)
);

CREATE TABLE approval_requests (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     TEXT NOT NULL,
    item_id    TEXT NOT NULL REFERENCES catalog_items(id) ON DELETE CASCADE,
    version    TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    spec       JSONB NOT NULL,
    requester  TEXT NOT NULL,
    approver   TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL DEFAULT 'pending',
    reason     TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ
);

CREATE INDEX approval_requests_org_idx ON approval_requests (org_id, state);

CREATE TYPE instance_state AS ENUM ('pending', 'deploying', 'running', 'upgrading', 'degraded', 'failed', 'deleting');

CREATE TABLE resource_instances (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cluster_id      TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    catalog_item_id TEXT NOT NULL,
    version         TEXT NOT NULL,
    owner_team      TEXT NOT NULL DEFAULT '',
    spec            JSONB NOT NULL,
    resource_ref    JSONB NOT NULL DEFAULT '{}',
    health          TEXT NOT NULL DEFAULT 'unknown',
    sync_state      TEXT NOT NULL DEFAULT '',
    status_message  TEXT NOT NULL DEFAULT '',
    state           instance_state NOT NULL DEFAULT 'pending',
    management_mode management_mode NOT NULL DEFAULT 'adopt',
    commit_sha      TEXT NOT NULL DEFAULT '',
    pr_url          TEXT NOT NULL DEFAULT '',
    generation      INT NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX resource_instances_org_idx ON resource_instances (org_id, cluster_id);
CREATE INDEX resource_instances_ref_idx ON resource_instances (cluster_id, (resource_ref->>'kind'), (resource_ref->>'name'), (resource_ref->>'namespace'));

CREATE TABLE tenant_git_configs (
    org_id        TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    repo          TEXT NOT NULL,
    commit_policy TEXT NOT NULL DEFAULT 'direct',
    base_branch   TEXT NOT NULL DEFAULT 'main'
);

-- +goose Down
DROP TABLE IF EXISTS tenant_git_configs;
DROP TABLE IF EXISTS resource_instances;
DROP TYPE IF EXISTS instance_state;
DROP TABLE IF EXISTS approval_requests;
DROP TABLE IF EXISTS catalog_pins;
DROP TABLE IF EXISTS catalog_visibility;
DROP TABLE IF EXISTS catalog_item_versions;
DROP TABLE IF EXISTS catalog_items;
DROP TYPE IF EXISTS approval_policy;
DROP TYPE IF EXISTS catalog_source;
