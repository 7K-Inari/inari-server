-- +goose Up
-- W3 credential vault (plan §5.8, Extension OIDC Pass-Through & Per-User Git
-- Social Login): envelope-encrypted per-user credential material. Only
-- ciphertext is ever stored (refresh_token_enc/session_token_enc/token_enc
-- under a per-row DEK, itself wrapped by the platform KEK into dek_enc);
-- plaintext exists only in process memory at the vault boundary.

-- Per-user git provider connections (social login): one row per
-- (org, user, provider); the OAuth refresh token is envelope-encrypted.
CREATE TABLE user_git_connections (
    id                TEXT PRIMARY KEY,             -- ugc:<uuid>
    org_id            TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_sub          TEXT NOT NULL,
    provider          TEXT NOT NULL,
    provider_login    TEXT NOT NULL,
    scopes            TEXT NOT NULL DEFAULT '',
    refresh_token_enc BYTEA NOT NULL,
    dek_enc           BYTEA NOT NULL,
    api_base          TEXT NOT NULL DEFAULT '',     -- '': github.com; else GHE API base
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at      TIMESTAMPTZ,
    UNIQUE (org_id, user_sub, provider)
);

-- Per-user extension sessions (oidc-sso-session auth method): backs the
-- extensionhost.SessionStore seam; the downstream session token is
-- envelope-encrypted.
CREATE TABLE user_extension_sessions (
    id                TEXT PRIMARY KEY,             -- ues:<uuid>
    org_id            TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_sub          TEXT NOT NULL,
    extension         TEXT NOT NULL,
    cluster_id        TEXT NOT NULL,
    session_token_enc BYTEA NOT NULL,
    dek_enc           BYTEA NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_sub, extension, cluster_id)
);

-- Agent command credentials: short-lived user tokens minted at the
-- extension hop, redeemed once by the agent via
-- AgentCredentials.RedeemUserCredential and hard-deleted on redeem.
CREATE TABLE agent_command_credentials (
    credential_ref TEXT PRIMARY KEY,                -- cred:<uuid>
    command_id     TEXT NOT NULL REFERENCES agent_commands(id) ON DELETE CASCADE,
    cluster_id     TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    token_enc      BYTEA NOT NULL,
    dek_enc        BYTEA NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    redeemed_at    TIMESTAMPTZ
);
CREATE INDEX agent_command_credentials_expiry_idx
    ON agent_command_credentials (expires_at) WHERE redeemed_at IS NULL;

-- Per-user git fallback policy: when a template run has no user git
-- connection, 'block' fails closed and 'platform_app' reverts to the
-- platform GitHub App (model A).
ALTER TABLE tenant_git_configs
    ADD COLUMN user_template_fallback TEXT NOT NULL DEFAULT 'block'
    CHECK (user_template_fallback IN ('block', 'platform_app'));

-- +goose Down
ALTER TABLE tenant_git_configs DROP COLUMN user_template_fallback;
DROP TABLE agent_command_credentials;
DROP TABLE user_extension_sessions;
DROP TABLE user_git_connections;
