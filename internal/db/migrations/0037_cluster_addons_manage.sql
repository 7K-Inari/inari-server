-- +goose Up
-- Feature C (addons CD loop): adoption/update bookkeeping on cluster_addons.
-- commit_sha/pr_url record the latest git write per the repo's commit
-- policy; prune_enabled flips only via the explicit human enable-prune
-- action (decision 2: prune stays off after adoption until then);
-- cluster_selector holds the server-side label query (decision 8) for
-- ApplicationSet fleet rows so cluster register/label-change events can
-- re-evaluate membership without ArgoCD cluster-secret coupling.
ALTER TABLE cluster_addons
    ADD COLUMN commit_sha       TEXT NOT NULL DEFAULT '',
    ADD COLUMN pr_url           TEXT NOT NULL DEFAULT '',
    ADD COLUMN prune_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN namespace        TEXT NOT NULL DEFAULT '',  -- destination ns (re-renders)
    ADD COLUMN cluster_selector JSONB;

-- +goose Down
ALTER TABLE cluster_addons
    DROP COLUMN IF EXISTS cluster_selector,
    DROP COLUMN IF EXISTS namespace,
    DROP COLUMN IF EXISTS prune_enabled,
    DROP COLUMN IF EXISTS pr_url,
    DROP COLUMN IF EXISTS commit_sha;
