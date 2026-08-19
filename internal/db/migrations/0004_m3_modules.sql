-- +goose Up
-- M3 modules: cloud accounts, approvals extension, notifications, policy
-- service, impersonation support (plan §5.2, §5.7, §5.11).

-- Cloud Accounts (§5.7): stores ONLY account ID, role ARN, external ID and
-- issuer metadata — never keys.
CREATE TABLE cloud_accounts (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL DEFAULT 'aws',
    account_id       TEXT NOT NULL,
    role_arn         TEXT NOT NULL,
    external_id      TEXT NOT NULL DEFAULT '',
    issuer_url       TEXT NOT NULL DEFAULT '',
    run_context      TEXT NOT NULL DEFAULT 'tenant',
    state            TEXT NOT NULL DEFAULT 'pending_validation',
    validated_at     TIMESTAMPTZ,
    validation_error TEXT NOT NULL DEFAULT '',
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, provider, account_id)
);

-- Cluster metadata needed for the IRSA-vs-web-identity ProviderConfig
-- decision (agent-reported at registration).
ALTER TABLE clusters
    ADD COLUMN distribution TEXT NOT NULL DEFAULT '',
    ADD COLUMN oidc_issuer_url TEXT NOT NULL DEFAULT '';

-- Approvals extension: expiry, cancellation, deploy resume context.
ALTER TABLE approval_requests
    ADD COLUMN expires_at TIMESTAMPTZ,
    ADD COLUMN cancelled_by TEXT NOT NULL DEFAULT '',
    ADD COLUMN name TEXT NOT NULL DEFAULT '',
    ADD COLUMN namespace TEXT NOT NULL DEFAULT '',
    ADD COLUMN owner_team TEXT NOT NULL DEFAULT '',
    ADD COLUMN channel TEXT NOT NULL DEFAULT '',
    ADD COLUMN instance_id TEXT NOT NULL DEFAULT '';

-- Policy Service (§5.11): one policy model, request/render targets.
CREATE TABLE policies (
    id         TEXT PRIMARY KEY,
    org_id     TEXT REFERENCES organizations(id) ON DELETE CASCADE, -- NULL = platform-global
    name       TEXT NOT NULL,
    target     TEXT NOT NULL, -- 'request' | 'render'
    engine     TEXT NOT NULL DEFAULT 'rego',
    source     TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    version    INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE cluster_sets (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    label_selector JSONB NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE policy_packs (
    id         TEXT PRIMARY KEY,
    org_id     TEXT REFERENCES organizations(id) ON DELETE CASCADE, -- NULL = platform-global
    name       TEXT NOT NULL,
    engine     TEXT NOT NULL, -- 'kyverno' | 'cel-vap'
    oci_ref    TEXT NOT NULL DEFAULT '',
    version    TEXT NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}',
    manifests  JSONB NOT NULL DEFAULT '[]', -- rendered pack documents (v1: stored directly)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy_assignments (
    id          TEXT PRIMARY KEY,
    pack_id     TEXT NOT NULL REFERENCES policy_packs(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL, -- 'clusterset' | 'tenant' | 'cluster'
    target_id   TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (pack_id, target_type, target_id)
);

-- Exemptions: time-boxed, approval-gated, audited (§5.11).
CREATE TABLE exemptions (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_id   TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    scope       JSONB NOT NULL DEFAULT '{}',
    reason      TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'approved' | 'rejected' | 'expired'
    expires_at  TIMESTAMPTZ NOT NULL,
    approved_by TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Notifications (§5.2): Slack + generic webhook endpoints and deliveries.
CREATE TABLE notification_endpoints (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL, -- 'slack' | 'webhook'
    url        TEXT NOT NULL,
    secret     TEXT NOT NULL DEFAULT '', -- HMAC signing secret (webhook kind)
    events     TEXT[] NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE notification_deliveries (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id  TEXT NOT NULL REFERENCES notification_endpoints(id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL,
    payload      JSONB NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'delivered' | 'failed'
    attempts     INT NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX notification_deliveries_status_idx ON notification_deliveries (status, created_at);
CREATE INDEX policies_org_idx ON policies (org_id);
CREATE INDEX cluster_sets_org_idx ON cluster_sets (org_id);
CREATE INDEX policy_assignments_pack_idx ON policy_assignments (pack_id);
CREATE INDEX exemptions_lookup_idx ON exemptions (org_id, policy_id, state, expires_at);
CREATE INDEX notification_endpoints_org_idx ON notification_endpoints (org_id);

-- +goose Down
DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notification_endpoints;
DROP TABLE IF EXISTS exemptions;
DROP TABLE IF EXISTS policy_assignments;
DROP TABLE IF EXISTS policy_packs;
DROP TABLE IF EXISTS cluster_sets;
DROP TABLE IF EXISTS policies;
ALTER TABLE approval_requests
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS cancelled_by,
    DROP COLUMN IF EXISTS name,
    DROP COLUMN IF EXISTS namespace,
    DROP COLUMN IF EXISTS owner_team,
    DROP COLUMN IF EXISTS channel,
    DROP COLUMN IF EXISTS instance_id;
ALTER TABLE clusters
    DROP COLUMN IF EXISTS distribution,
    DROP COLUMN IF EXISTS oidc_issuer_url;
DROP TABLE IF EXISTS cloud_accounts;
