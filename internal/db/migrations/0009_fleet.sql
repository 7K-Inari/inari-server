-- +goose Up
-- M4 Fleet Manager (plan §5.11): staged fleet rollouts, agent upgrade
-- channels, drift detection. Execution stays credential-free: desired state
-- is handed to agents via the durable command queue only.

ALTER TABLE clusters
    ADD COLUMN agent_version TEXT NOT NULL DEFAULT '';

CREATE TABLE rollouts (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL, -- 'capability' | 'policy_pack' | 'agent_upgrade' | 'catalog_version'
    target_ref      TEXT NOT NULL DEFAULT '',
    desired_version TEXT NOT NULL DEFAULT '',
    stages          JSONB NOT NULL DEFAULT '[]',
    state           TEXT NOT NULL DEFAULT 'pending',
    current_stage   INT NOT NULL DEFAULT 0,
    gate_context    JSONB,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE rollout_targets (
    rollout_id       TEXT NOT NULL REFERENCES rollouts(id) ON DELETE CASCADE,
    cluster_id       TEXT NOT NULL,
    stage            INT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'delivered' | 'healthy' | 'failed'
    command_id       TEXT NOT NULL DEFAULT '',
    observed_health  TEXT NOT NULL DEFAULT '',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rollout_id, cluster_id, stage)
);

CREATE TABLE agent_channels (
    id                    TEXT PRIMARY KEY,
    org_id                TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cluster_set_id        TEXT NOT NULL REFERENCES cluster_sets(id) ON DELETE CASCADE,
    channel               TEXT NOT NULL, -- 'stable' | 'canary'
    desired_agent_version TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cluster_set_id, channel)
);

CREATE TABLE drift_events (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cluster_id    TEXT NOT NULL,
    kind          TEXT NOT NULL, -- 'instance_spec' | 'capability' | 'agent_version'
    resource_ref  TEXT NOT NULL DEFAULT '',
    desired_hash  TEXT NOT NULL DEFAULT '',
    reported_hash TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open', -- 'open' | 'resolved'
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX rollouts_org_idx ON rollouts (org_id);
CREATE INDEX rollout_targets_rollout_idx ON rollout_targets (rollout_id, stage);
CREATE INDEX agent_channels_set_idx ON agent_channels (cluster_set_id);
CREATE INDEX drift_events_org_idx ON drift_events (org_id, status, detected_at);

-- +goose Down
DROP TABLE IF EXISTS drift_events;
DROP TABLE IF EXISTS agent_channels;
DROP TABLE IF EXISTS rollout_targets;
DROP TABLE IF EXISTS rollouts;
ALTER TABLE clusters DROP COLUMN IF EXISTS agent_version;
