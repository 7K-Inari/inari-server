-- +goose Up
CREATE TABLE approval_config (
    org_id     TEXT        PRIMARY KEY,
    config     JSONB       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS approval_config;
