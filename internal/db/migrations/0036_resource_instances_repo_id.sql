-- +goose Up
-- Instance repo attribution (Feature A writers): an instance records which
-- tenant_git_repos row its manifests were committed to. NULL predates the
-- column; readers fall back to the cluster's baseline binding (today's
-- derived attribution). approval_requests.repo_id carries the deploy-time
-- selector through the approval gate so resume commits to the same repo.
ALTER TABLE resource_instances
    ADD COLUMN repo_id TEXT REFERENCES tenant_git_repos(id) ON DELETE SET NULL;

-- Backfill: existing instances attribute to their cluster's bound baseline
-- (exactly what GitRepoRefCounts derived before this column existed).
UPDATE resource_instances i SET repo_id = c.baseline_repo_id
FROM clusters c
WHERE c.id = i.cluster_id AND c.baseline_repo_id IS NOT NULL;

CREATE INDEX resource_instances_repo_idx ON resource_instances (repo_id) WHERE repo_id IS NOT NULL;

ALTER TABLE approval_requests
    ADD COLUMN repo_id TEXT REFERENCES tenant_git_repos(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE approval_requests DROP COLUMN IF EXISTS repo_id;
DROP INDEX IF EXISTS resource_instances_repo_idx;
ALTER TABLE resource_instances DROP COLUMN IF EXISTS repo_id;
