-- +goose Up
-- Tenant deletion/decommission (ADR-0006): organizations carry a lifecycle
-- status so a deleting tenant is frozen (write paths and reconcilers skip
-- it); tenant_deletions drives the resumable teardown state machine;
-- audit_archive retains the org's audit history before the org row (and its
-- cascading children) is removed.
ALTER TABLE organizations ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','deleting','deleted'));

CREATE TABLE tenant_deletions (
    org_id       TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    state        TEXT NOT NULL DEFAULT 'deleting' CHECK (state IN ('deleting','delete_failed')),
    step         TEXT NOT NULL DEFAULT '', -- last completed teardown step
    force        BOOLEAN NOT NULL DEFAULT false,
    reason       TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL,
    approval_id  TEXT NOT NULL DEFAULT '',
    snapshot     JSONB NOT NULL DEFAULT '{}', -- FGA tuple snapshot for cleanup
    last_error   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_archive (LIKE audit_events INCLUDING ALL);
ALTER TABLE audit_archive ADD COLUMN archived_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE UNIQUE INDEX audit_archive_id_idx ON audit_archive (id);

-- Allow deleting an org's live audit rows only inside a transaction that
-- opted in via SET LOCAL audit.allow_delete='on' (the tenant deleter's
-- archive step). Everything else stays append-only.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('audit.allow_delete', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
DROP TABLE IF EXISTS audit_archive;
DROP TABLE IF EXISTS tenant_deletions;
ALTER TABLE organizations DROP COLUMN status;
