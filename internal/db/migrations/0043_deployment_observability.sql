-- +goose Up
-- Deployment observability is additive and deliberately follows the plugin
-- compatibility migration 0042 when that coordinated change lands.
-- Approval resume carries the exact admitted application pin without exposing
-- it as mutable approval API input. Existing pending rows retain an empty pin
-- and follow their legacy admission behavior.
ALTER TABLE approval_requests ADD COLUMN artifact_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_requests ADD COLUMN deployment_plan_id TEXT NOT NULL DEFAULT '';

CREATE TABLE deployment_plans (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    requester TEXT NOT NULL,
    idempotency_key TEXT NOT NULL DEFAULT '',
    operation TEXT NOT NULL CHECK (operation IN ('deploy', 'provisionExisting')),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('catalog', 'chart', 'template')),
    app_instance_id TEXT REFERENCES resource_instances(id) ON DELETE SET NULL,
    scaffold_run_id TEXT REFERENCES scaffold_runs(id) ON DELETE SET NULL,
    app_cluster_id TEXT NOT NULL DEFAULT '',
    app_version TEXT NOT NULL,
    app_ref TEXT NOT NULL DEFAULT '',
    app_digest TEXT NOT NULL,
    pack_item_id TEXT NOT NULL DEFAULT '',
    pack_version TEXT NOT NULL DEFAULT '',
    pack_digest TEXT NOT NULL DEFAULT '',
    pack_render_contract TEXT NOT NULL DEFAULT '',
    capability_digest TEXT NOT NULL DEFAULT '',
    plan_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL,
    gate_state JSONB NOT NULL DEFAULT '{}',
    plan_document JSONB NOT NULL,
    approval_id TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, requester, idempotency_key)
);
CREATE INDEX deployment_plans_org_state_idx ON deployment_plans (org_id, state);
CREATE INDEX deployment_plans_app_instance_idx ON deployment_plans (app_instance_id, updated_at DESC);
CREATE INDEX deployment_plans_scaffold_run_idx ON deployment_plans (scaffold_run_id);

CREATE TABLE observability_companions (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL UNIQUE REFERENCES deployment_plans(id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    app_instance_id TEXT REFERENCES resource_instances(id) ON DELETE SET NULL,
    scaffold_run_id TEXT REFERENCES scaffold_runs(id) ON DELETE SET NULL,
    companion_instance_id TEXT REFERENCES resource_instances(id) ON DELETE SET NULL,
    target_id TEXT REFERENCES resource_targets(id) ON DELETE SET NULL,
    target_revision BIGINT NOT NULL,
    target_cluster_id TEXT NOT NULL,
    target_selection JSONB NOT NULL,
    app_source_digest TEXT NOT NULL,
    app_revision TEXT NOT NULL,
    pack_item_id TEXT NOT NULL,
    pack_version TEXT NOT NULL,
    pack_digest TEXT NOT NULL,
    pack_render_contract TEXT NOT NULL,
    capability_digest TEXT NOT NULL,
    render_intent JSONB NOT NULL DEFAULT '{}',
    state TEXT NOT NULL CHECK (state IN ('blocked_external_gate', 'waiting_for_app', 'approval_pending', 'render_pending', 'deploying', 'verification_pending', 'ready', 'verification_failed', 'unavailable', 'cancelled')),
    generation BIGINT NOT NULL CHECK (generation > 0),
    latest_verification_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    companion_document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, generation)
);
CREATE UNIQUE INDEX observability_companions_active_target_idx
    ON observability_companions (org_id, app_instance_id, target_id)
    WHERE app_instance_id IS NOT NULL AND target_id IS NOT NULL
      AND state NOT IN ('verification_failed', 'cancelled', 'blocked_external_gate');
CREATE INDEX observability_companions_app_idx ON observability_companions (app_instance_id, updated_at DESC);
CREATE INDEX observability_companions_state_idx ON observability_companions (org_id, state);

CREATE TABLE observability_verification_results (
    companion_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    run_id TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    suite_digest TEXT NOT NULL,
    suite_profile TEXT NOT NULL,
    target_revision BIGINT NOT NULL,
    app_revision TEXT NOT NULL,
    pack_digest TEXT NOT NULL,
    capability_digest TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('passed', 'failed')),
    checks JSONB NOT NULL,
    result_document JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (companion_id, generation, run_id, suite_digest),
    FOREIGN KEY (companion_id, generation) REFERENCES observability_companions(id, generation) ON DELETE CASCADE
);
CREATE INDEX observability_verification_current_idx ON observability_verification_results (companion_id, generation, received_at DESC);

-- +goose Down
DROP TABLE IF EXISTS observability_verification_results;
DROP TABLE IF EXISTS observability_companions;
DROP TABLE IF EXISTS deployment_plans;
ALTER TABLE approval_requests DROP COLUMN IF EXISTS deployment_plan_id;
ALTER TABLE approval_requests DROP COLUMN IF EXISTS artifact_digest;
