-- +goose Up
-- Scaffolding hardening (M8.W6, parent plan §8): per-tenant override of
-- the git organization/owner receiving scaffolded repos. NULL falls back
-- to the platform-wide INARI_SCAFFOLD_GIT_ORG.
ALTER TABLE tenant_git_configs ADD COLUMN scaffold_git_org TEXT;

-- +goose Down
ALTER TABLE tenant_git_configs DROP COLUMN IF EXISTS scaffold_git_org;
