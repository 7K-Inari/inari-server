-- +goose Up
CREATE TABLE trusted_source_states (
    kind                  TEXT NOT NULL CHECK (kind IN ('catalog', 'template')),
    source_id             TEXT NOT NULL,
    fingerprint           TEXT NOT NULL,
    state                 TEXT NOT NULL CHECK (state IN ('never-synced', 'ready', 'stale', 'failed', 'policy-changed', 'unconfigured')),
    generation            BIGINT NOT NULL DEFAULT 0,
    item_count            INTEGER NOT NULL DEFAULT 0,
    last_attempt_at       TIMESTAMPTZ,
    last_success_at       TIMESTAMPTZ,
    last_good_index_ref   TEXT NOT NULL DEFAULT '',
    last_good_index_digest TEXT NOT NULL DEFAULT '',
    last_error_code       TEXT NOT NULL DEFAULT '',
    last_error            TEXT NOT NULL DEFAULT '',
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, source_id)
);

ALTER TABLE catalog_items
    ADD COLUMN source_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN trust_tier TEXT NOT NULL DEFAULT '',
    ADD COLUMN unsigned BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN source_fingerprint TEXT NOT NULL DEFAULT '',
    ADD COLUMN source_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN snapshot_present BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE catalog_item_versions
    ADD COLUMN package_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN artifact_ref TEXT NOT NULL DEFAULT '',
    ADD COLUMN artifact_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN chart_ref TEXT NOT NULL DEFAULT '',
    ADD COLUMN chart_digest TEXT NOT NULL DEFAULT '',
    ADD COLUMN snapshot_present BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE resource_instances ADD COLUMN artifact_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE scaffold_runs ADD COLUMN template_digest TEXT NOT NULL DEFAULT '';

CREATE INDEX catalog_items_source_active_idx ON catalog_items (source_id, snapshot_present, name);
CREATE INDEX catalog_items_trust_tier_idx ON catalog_items (trust_tier);
CREATE INDEX catalog_item_versions_artifact_idx ON catalog_item_versions (item_id, snapshot_present, version);
CREATE INDEX trusted_source_states_success_idx ON trusted_source_states (kind, source_id, last_success_at);

-- Pre-v1 clean break: old external identities remain historical but can no
-- longer deploy or render. component:/discovered: items are intentionally
-- untouched. No old-ID rewrite or compatibility alias is introduced.
UPDATE catalog_items SET snapshot_present = false
WHERE id LIKE 'curated:%' OR id LIKE 'platform:%' OR id LIKE 'template:%';
UPDATE catalog_item_versions SET snapshot_present = false
WHERE item_id LIKE 'curated:%' OR item_id LIKE 'platform:%' OR item_id LIKE 'template:%';

-- +goose Down
DROP INDEX IF EXISTS trusted_source_states_success_idx;
DROP INDEX IF EXISTS catalog_item_versions_artifact_idx;
DROP INDEX IF EXISTS catalog_items_trust_tier_idx;
DROP INDEX IF EXISTS catalog_items_source_active_idx;
ALTER TABLE scaffold_runs DROP COLUMN IF EXISTS template_digest;
ALTER TABLE resource_instances DROP COLUMN IF EXISTS artifact_digest;
ALTER TABLE catalog_item_versions
    DROP COLUMN IF EXISTS snapshot_present,
    DROP COLUMN IF EXISTS chart_digest,
    DROP COLUMN IF EXISTS chart_ref,
    DROP COLUMN IF EXISTS artifact_digest,
    DROP COLUMN IF EXISTS artifact_ref,
    DROP COLUMN IF EXISTS package_version;
ALTER TABLE catalog_items
    DROP COLUMN IF EXISTS snapshot_present,
    DROP COLUMN IF EXISTS source_generation,
    DROP COLUMN IF EXISTS source_fingerprint,
    DROP COLUMN IF EXISTS unsigned,
    DROP COLUMN IF EXISTS trust_tier,
    DROP COLUMN IF EXISTS source_id;
DROP TABLE IF EXISTS trusted_source_states;
