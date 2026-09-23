-- +goose Up
-- Per-extension identity (ADR-0008, issue #75): each backend extension gets
-- a dedicated Keycloak service-account client (clientId ext-<name>) gating
-- the extension-gateway tunnel; only the clientId projection is persisted
-- (secrets live in Keycloak, returned once at create/rotate).
ALTER TABLE extensions ADD COLUMN client_id TEXT NOT NULL DEFAULT '';

CREATE INDEX extensions_client_id_idx ON extensions (client_id) WHERE client_id <> '';

-- +goose Down
DROP INDEX IF EXISTS extensions_client_id_idx;
ALTER TABLE extensions DROP COLUMN IF EXISTS client_id;
