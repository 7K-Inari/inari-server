-- +goose Up
-- Hybrid multi-tenant GitHub App model (model B): optional per-tenant BYO
-- GitHub App credential REFERENCE on tenant_git_configs. The private key
-- itself is never stored (ADR-0004: ESO mounts only).
ALTER TABLE tenant_git_configs
    ADD COLUMN github_app_id BIGINT,
    ADD COLUMN github_app_installation_id BIGINT,
    ADD COLUMN github_app_key_secret TEXT,   -- namespace/name of the ESO-rendered Secret
    ADD COLUMN github_app_key_key    TEXT,   -- data key inside the Secret
    ADD COLUMN github_app_api_base   TEXT;   -- NULL/'': github.com; else GHE https://<host>/api/v3

-- Credential columns are all-or-nothing.
ALTER TABLE tenant_git_configs ADD CONSTRAINT tenant_git_app_all_or_none CHECK (
    (github_app_id IS NULL AND github_app_installation_id IS NULL
        AND github_app_key_secret IS NULL AND github_app_key_key IS NULL)
    OR (github_app_id IS NOT NULL AND github_app_installation_id IS NOT NULL
        AND github_app_key_secret IS NOT NULL AND github_app_key_key IS NOT NULL));

-- api_base only makes sense with a BYO app (model A's host is server config).
ALTER TABLE tenant_git_configs ADD CONSTRAINT tenant_git_app_api_base_requires_app CHECK (
    github_app_api_base IS NULL OR github_app_id IS NOT NULL);

-- +goose Down
ALTER TABLE tenant_git_configs DROP CONSTRAINT tenant_git_app_api_base_requires_app;
ALTER TABLE tenant_git_configs DROP CONSTRAINT tenant_git_app_all_or_none;
ALTER TABLE tenant_git_configs
    DROP COLUMN github_app_id,
    DROP COLUMN github_app_installation_id,
    DROP COLUMN github_app_key_secret,
    DROP COLUMN github_app_key_key,
    DROP COLUMN github_app_api_base;
