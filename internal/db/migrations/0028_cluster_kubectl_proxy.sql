-- +goose Up
-- kubectl-proxy e2e access: per-cluster disable flag. Composes with the
-- global INARI_DISABLE_KUBECTL_PROXY kill switch — effective enablement is
-- !global && !kubectl_proxy_disabled (computed server-side).

ALTER TABLE clusters
    ADD COLUMN kubectl_proxy_disabled BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE clusters DROP COLUMN IF EXISTS kubectl_proxy_disabled;
