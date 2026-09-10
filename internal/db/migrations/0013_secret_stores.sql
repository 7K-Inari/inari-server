-- +goose Up
CREATE TABLE secret_stores (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    name       TEXT NOT NULL,
    scope      TEXT NOT NULL CHECK (scope IN ('platform','cluster')),
    targets    JSONB NOT NULL,
    provider   JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- +goose Down
DROP TABLE IF EXISTS secret_stores;
