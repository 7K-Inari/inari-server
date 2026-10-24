-- +goose Up
-- Per-cluster baseline binding (multi-baseline support): each cluster binds
-- to exactly one platform-scope repo from tenant_git_repos. NULL means the
-- cluster predates the registry or its baseline was unregistered; readers
-- fall back to the org default.
ALTER TABLE clusters
    ADD COLUMN baseline_repo_id TEXT REFERENCES tenant_git_repos(id) ON DELETE SET NULL;

-- Backfill: existing clusters bind to their org's default (the backfilled
-- 'baseline' row from migration 0033).
UPDATE clusters c SET baseline_repo_id = r.id
FROM tenant_git_repos r
WHERE r.org_id = c.org_id AND r.is_default;

CREATE INDEX clusters_baseline_repo_idx ON clusters (baseline_repo_id) WHERE baseline_repo_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS clusters_baseline_repo_idx;
ALTER TABLE clusters DROP COLUMN IF EXISTS baseline_repo_id;
