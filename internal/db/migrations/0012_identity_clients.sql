-- +goose Up
-- Server-side metadata projection of tenant OIDC clients (Settings design
-- §3.1). Secrets are never stored here — they live only in Keycloak and are
-- returned once at create/rotate.
CREATE TABLE identity_clients (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id     TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    type          TEXT NOT NULL CHECK (type IN ('service', 'public')),
    audiences     JSONB NOT NULL DEFAULT '[]',
    scopes        JSONB NOT NULL DEFAULT '[]',
    redirect_uris JSONB NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- +goose Down
DROP TABLE identity_clients;
