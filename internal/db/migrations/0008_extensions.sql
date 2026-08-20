-- +goose Up
-- M4 Extension Host (plan §5.8/§5.9): backend plugin registry. Plugins run
-- as isolated sidecars verified via the inari-plugin-sdk handshake; the
-- control plane proxies /api/extensions/<name>/* with authz enforced.

CREATE TABLE extensions (
    id         TEXT PRIMARY KEY,
    org_id     TEXT REFERENCES organizations(id) ON DELETE CASCADE, -- NULL = platform-global
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'backend',
    manifest   JSONB NOT NULL DEFAULT '{}',
    endpoint   TEXT NOT NULL DEFAULT '',
    checksum   TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'ready' | 'degraded' | 'stopped'
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name)
);

CREATE INDEX extensions_org_idx ON extensions (org_id);

-- +goose Down
DROP TABLE IF EXISTS extensions;
