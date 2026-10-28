-- +goose Up
-- Provider-agnostic git webhook ingress (parent plan §9 risk #1): per-repo
-- webhook secrets live envelope-encrypted on the repo row (migration 0028
-- credential-vault pattern — fresh DEK per row, wrapped by the platform
-- KEK, AAD "tenant_git_repos:<id>"); webhook_external_id/webhook_url track
-- the provider-side hook registration (EnsureWebhook).
ALTER TABLE tenant_git_repos
    ADD COLUMN webhook_secret_enc  BYTEA,
    ADD COLUMN webhook_dek_enc     BYTEA,
    ADD COLUMN webhook_external_id TEXT,
    ADD COLUMN webhook_url         TEXT;

-- Secret ciphertext and wrapped DEK travel together (0028 discipline).
ALTER TABLE tenant_git_repos
    ADD CONSTRAINT tenant_git_repo_webhook_secret_all_or_none CHECK (
        (webhook_secret_enc IS NULL AND webhook_dek_enc IS NULL)
        OR (webhook_secret_enc IS NOT NULL AND webhook_dek_enc IS NOT NULL));

-- +goose Down
ALTER TABLE tenant_git_repos
    DROP CONSTRAINT IF EXISTS tenant_git_repo_webhook_secret_all_or_none,
    DROP COLUMN IF EXISTS webhook_secret_enc,
    DROP COLUMN IF EXISTS webhook_dek_enc,
    DROP COLUMN IF EXISTS webhook_external_id,
    DROP COLUMN IF EXISTS webhook_url;
