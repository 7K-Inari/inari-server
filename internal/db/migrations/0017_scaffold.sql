-- +goose Up
-- Scaffolding / Software Templates (M8, plan §4/§10): scaffold runs and
-- their resumable steps. Long-running steps persist attempts/results so
-- restarts resume instead of re-executing (same pattern as
-- tenant_zone_steps, migration 0007).
-- 'template' is a new catalog source for template items. ADD VALUE is
-- append-only: the Down migration cannot remove it from the enum.
ALTER TYPE catalog_source ADD VALUE IF NOT EXISTS 'template';

CREATE TABLE scaffold_runs (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    template_item_id TEXT NOT NULL REFERENCES catalog_items(id),
    template_version TEXT NOT NULL,
    display_name     TEXT NOT NULL,
    values           JSONB NOT NULL DEFAULT '{}',
    -- pending|rendering|creating-repo|creating-pipeline|registering-catalog|binding-rbac|completed|failed
    phase            TEXT NOT NULL DEFAULT 'pending',
    error            TEXT NOT NULL DEFAULT '',
    outputs          JSONB NOT NULL DEFAULT '{}',
    idempotency_key  TEXT,
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled_at     TIMESTAMPTZ
);

-- Retries of the same logical run are deduplicated per tenant.
CREATE UNIQUE INDEX scaffold_runs_idempotency_idx
    ON scaffold_runs (org_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX scaffold_runs_org_idx ON scaffold_runs (org_id);
CREATE INDEX scaffold_runs_phase_idx ON scaffold_runs (phase);

CREATE TABLE scaffold_run_steps (
    run_id       TEXT NOT NULL REFERENCES scaffold_runs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending', -- pending|running|waiting|completed|failed
    attempts     INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    error        TEXT NOT NULL DEFAULT '',
    result       JSONB NOT NULL DEFAULT '{}',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, name)
);

-- +goose Down
DROP TABLE IF EXISTS scaffold_run_steps;
DROP TABLE IF EXISTS scaffold_runs;
-- NOTE: enum value catalog_source.'template' is intentionally left in
-- place; Postgres cannot remove enum values.
