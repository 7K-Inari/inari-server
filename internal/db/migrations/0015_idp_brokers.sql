-- +goose Up
-- Server-side metadata projection of tenant-brokered OIDC identity providers
-- (Settings design §3.3). Secrets are never stored here — they are
-- write-only in Keycloak (masked on read). One IdP per org in v1, enforced
-- by the UNIQUE(org_id) constraint.
CREATE TABLE idp_brokers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        TEXT NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    alias         TEXT NOT NULL,
    issuer_url    TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    claim_mapping JSONB NOT NULL DEFAULT '{}',
    domain_hints  JSONB NOT NULL DEFAULT '[]',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, alias)
);

-- +goose Down
DROP TABLE idp_brokers;
