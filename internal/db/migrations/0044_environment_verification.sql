-- +goose Up
-- Self-service environment verification. All execution objects remain render
-- intents until the separately approved multi-repo renderer gate opens.
ALTER TABLE resource_instances
    ADD COLUMN uid UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN observed_revision TEXT NOT NULL DEFAULT '',
    ADD COLUMN sync_operation_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN sync_operation_phase TEXT NOT NULL DEFAULT '',
    ADD COLUMN operation_finished_at TIMESTAMPTZ;
CREATE UNIQUE INDEX resource_instances_uid_idx ON resource_instances(uid);

CREATE TABLE verification_suite_releases (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_id           TEXT NOT NULL,
    suite_digest        TEXT NOT NULL,
    descriptor          JSONB NOT NULL,
    normalized_suite    JSONB NOT NULL,
    workflow_template   BYTEA NOT NULL,
    content_digest      TEXT NOT NULL,
    evidence_digest     TEXT NOT NULL DEFAULT '',
    source_fingerprint  TEXT NOT NULL,
    eligibility         TEXT NOT NULL,
    trust_tier          TEXT NOT NULL,
    unsigned            BOOLEAN NOT NULL DEFAULT FALSE,
    legacy_exception    BOOLEAN NOT NULL DEFAULT FALSE,
    admitted_at         TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, suite_digest)
);
CREATE INDEX verification_suite_releases_org_idx ON verification_suite_releases(org_id, id);

CREATE TABLE verification_environment_policies (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id       TEXT NOT NULL REFERENCES resource_targets(id) ON DELETE CASCADE,
    target_revision BIGINT NOT NULL,
    environment     TEXT NOT NULL CHECK (environment IN ('development','staging','production')),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    limits          JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, target_id)
);
CREATE INDEX verification_environment_policies_org_idx ON verification_environment_policies(org_id);

CREATE TABLE verification_suite_grants (
    id                      TEXT PRIMARY KEY,
    org_id                  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    environment_policy_id   TEXT NOT NULL REFERENCES verification_environment_policies(id) ON DELETE CASCADE,
    suite_release_id        TEXT NOT NULL REFERENCES verification_suite_releases(id) ON DELETE RESTRICT,
    suite_digest            TEXT NOT NULL,
    profile                 TEXT NOT NULL,
    grant_revision          BIGINT NOT NULL CHECK (grant_revision > 0),
    grant_spec              JSONB NOT NULL,
    expires_at              TIMESTAMPTZ,
    revoked_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(environment_policy_id, suite_digest, profile)
);
CREATE INDEX verification_suite_grants_lookup_idx ON verification_suite_grants(org_id, suite_digest, profile) WHERE revoked_at IS NULL;

CREATE TABLE verification_policies (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    instance_id         TEXT NOT NULL REFERENCES resource_instances(id) ON DELETE CASCADE,
    instance_uid        UUID NOT NULL,
    policy_revision     BIGINT NOT NULL CHECK (policy_revision > 0),
    enabled             BOOLEAN NOT NULL,
    current             BOOLEAN NOT NULL DEFAULT TRUE,
    app_artifact_digest TEXT NOT NULL,
    suite_grant_id      TEXT NOT NULL,
    suite_digest        TEXT NOT NULL,
    profile             TEXT NOT NULL,
    policy_spec         JSONB NOT NULL,
    render_fingerprint  TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(instance_id, policy_revision)
);
CREATE UNIQUE INDEX verification_policies_current_idx ON verification_policies(instance_id) WHERE current;
CREATE INDEX verification_policies_org_idx ON verification_policies(org_id, instance_id);

CREATE TABLE verification_runs (
    id                  TEXT PRIMARY KEY,
    run_key             TEXT NOT NULL UNIQUE,
    org_id              TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    instance_id         TEXT NOT NULL REFERENCES resource_instances(id) ON DELETE CASCADE,
    instance_uid        UUID NOT NULL,
    app_revision        TEXT NOT NULL,
    app_artifact_digest TEXT NOT NULL,
    suite_digest        TEXT NOT NULL,
    profile             TEXT NOT NULL,
    trigger             JSONB NOT NULL,
    trigger_fingerprint TEXT NOT NULL,
    status              TEXT NOT NULL,
    disposition         TEXT NOT NULL DEFAULT '',
    reason_code         TEXT NOT NULL DEFAULT '',
    message             TEXT NOT NULL DEFAULT '',
    policy_revision     BIGINT NOT NULL,
    grant_revision      BIGINT NOT NULL,
    latest_attempt      INT NOT NULL DEFAULT 1,
    outcome             JSONB,
    outcome_digest      TEXT NOT NULL DEFAULT '',
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX verification_runs_history_idx ON verification_runs(org_id, instance_id, created_at DESC);
CREATE INDEX verification_runs_scheduler_idx ON verification_runs(status, updated_at);
CREATE INDEX verification_runs_gate_idx ON verification_runs(instance_uid, app_artifact_digest, suite_digest, profile, status, expires_at);

CREATE TABLE verification_run_attempts (
    run_id             TEXT NOT NULL REFERENCES verification_runs(id) ON DELETE CASCADE,
    attempt            INT NOT NULL,
    workflow_name      TEXT NOT NULL DEFAULT '',
    workflow_namespace TEXT NOT NULL DEFAULT '',
    workflow_uid       TEXT NOT NULL DEFAULT '',
    cluster_id         TEXT NOT NULL DEFAULT '',
    render_fingerprint TEXT NOT NULL DEFAULT '',
    outcome_digest     TEXT NOT NULL DEFAULT '',
    outcome            JSONB,
    state              TEXT NOT NULL DEFAULT 'verification_pending',
    message            TEXT NOT NULL DEFAULT '',
    started_at         TIMESTAMPTZ,
    finished_at        TIMESTAMPTZ,
    observed_at        TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ,
    links_expire_at    TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(run_id, attempt)
);
CREATE UNIQUE INDEX verification_run_attempts_workflow_idx ON verification_run_attempts(cluster_id, workflow_uid) WHERE workflow_uid <> '';

CREATE TABLE verification_report_receipts (
    cluster_id      TEXT NOT NULL,
    workflow_uid    TEXT NOT NULL,
    resource_version TEXT NOT NULL,
    run_id          TEXT NOT NULL REFERENCES verification_runs(id) ON DELETE CASCADE,
    attempt         INT NOT NULL,
    payload_digest  TEXT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(cluster_id, workflow_uid, resource_version)
);
CREATE INDEX verification_report_receipts_run_idx ON verification_report_receipts(run_id, attempt);

CREATE TABLE verification_promotion_policies (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_instance_id  TEXT NOT NULL REFERENCES resource_instances(id) ON DELETE CASCADE,
    source_instance_id  TEXT NOT NULL REFERENCES resource_instances(id) ON DELETE CASCADE,
    required_suite_digest TEXT NOT NULL,
    required_profile    TEXT NOT NULL,
    policy_revision     BIGINT NOT NULL CHECK (policy_revision > 0),
    policy_spec         JSONB NOT NULL,
    current             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(target_instance_id, policy_revision)
);
CREATE UNIQUE INDEX verification_promotion_policies_current_idx ON verification_promotion_policies(target_instance_id) WHERE current;

ALTER TABLE notification_deliveries ADD COLUMN outbox_event_id BIGINT;
CREATE UNIQUE INDEX notification_deliveries_outbox_idx ON notification_deliveries(endpoint_id, outbox_event_id) WHERE outbox_event_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS notification_deliveries_outbox_idx;
ALTER TABLE notification_deliveries DROP COLUMN IF EXISTS outbox_event_id;
DROP TABLE IF EXISTS verification_promotion_policies;
DROP TABLE IF EXISTS verification_report_receipts;
DROP TABLE IF EXISTS verification_run_attempts;
DROP TABLE IF EXISTS verification_runs;
DROP TABLE IF EXISTS verification_policies;
DROP TABLE IF EXISTS verification_suite_grants;
DROP TABLE IF EXISTS verification_environment_policies;
DROP TABLE IF EXISTS verification_suite_releases;
DROP INDEX IF EXISTS resource_instances_uid_idx;
ALTER TABLE resource_instances
    DROP COLUMN IF EXISTS operation_finished_at,
    DROP COLUMN IF EXISTS sync_operation_phase,
    DROP COLUMN IF EXISTS sync_operation_id,
    DROP COLUMN IF EXISTS observed_revision,
    DROP COLUMN IF EXISTS uid;
