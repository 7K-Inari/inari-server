-- +goose Up
CREATE TYPE cluster_state AS ENUM ('pending_approval', 'pending_registration', 'active', 'degraded', 'revoked');

CREATE TABLE clusters (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    kubernetes_version  TEXT NOT NULL DEFAULT '',
    labels              JSONB NOT NULL DEFAULT '{}',
    keycloak_client_id  TEXT NOT NULL DEFAULT '',
    state               cluster_state NOT NULL DEFAULT 'pending_registration',
    capability_checksum TEXT NOT NULL DEFAULT '',
    connected_at        TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE registration_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id  TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX registration_tokens_cluster_idx ON registration_tokens (cluster_id);

CREATE TYPE capability_kind AS ENUM ('crd', 'olm-csv', 'crossplane-xrd', 'crossplane-provider', 'kro-rgd', 'helm-release', 'cluster-addon', 'cluster-metadata');
CREATE TYPE management_mode AS ENUM ('adopt', 'observe-only', 'ignore');

CREATE TABLE capabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id      TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    kind            capability_kind NOT NULL,
    name            TEXT NOT NULL,
    "group"         TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL DEFAULT '',
    schema          JSONB,
    ui_hints        JSONB,
    management_mode management_mode NOT NULL DEFAULT 'observe-only',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE (cluster_id, kind, "group", name, version)
);

CREATE TYPE command_status AS ENUM ('pending', 'delivered', 'acked', 'nacked');

CREATE TABLE agent_commands (
    id          TEXT PRIMARY KEY,
    cluster_id  TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    payload     JSONB NOT NULL,
    status      command_status NOT NULL DEFAULT 'pending',
    attempts    INT NOT NULL DEFAULT 0,
    result_message TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX agent_commands_pending_idx ON agent_commands (cluster_id, created_at) WHERE status IN ('pending', 'delivered');

-- +goose Down
DROP TABLE IF EXISTS agent_commands;
DROP TYPE IF EXISTS command_status;
DROP TABLE IF EXISTS capabilities;
DROP TYPE IF EXISTS management_mode;
DROP TYPE IF EXISTS capability_kind;
DROP TABLE IF EXISTS registration_tokens;
DROP TABLE IF EXISTS clusters;
DROP TYPE IF EXISTS cluster_state;
