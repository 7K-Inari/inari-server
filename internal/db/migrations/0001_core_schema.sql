-- +goose Up
CREATE TABLE organizations (
    id              TEXT PRIMARY KEY,
    slug            TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    keycloak_org_id TEXT NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE teams (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    keycloak_group_path TEXT NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE users (
    id           TEXT PRIMARY KEY,
    email        TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT ''
);

CREATE TYPE membership_role AS ENUM ('org-admin', 'platform-engineer', 'developer', 'viewer');

CREATE TABLE memberships (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
    role    membership_role NOT NULL,
    PRIMARY KEY (user_id, org_id, role)
);

CREATE TABLE audit_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        TEXT NOT NULL,
    actor         TEXT NOT NULL,
    impersonator  TEXT,
    action        TEXT NOT NULL,
    object_type   TEXT NOT NULL,
    object_id     TEXT NOT NULL,
    payload       JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

CREATE TABLE outbox (
    id           BIGSERIAL PRIMARY KEY,
    org_id       TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    payload      JSONB NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);

CREATE INDEX outbox_unpublished_idx ON outbox (id) WHERE published_at IS NULL;

-- +goose Down
DROP TABLE IF EXISTS outbox;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
DROP FUNCTION IF EXISTS reject_audit_mutation();
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS memberships;
DROP TYPE IF EXISTS membership_role;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS organizations;
