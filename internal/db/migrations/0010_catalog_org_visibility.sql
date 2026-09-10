-- +goose Up
CREATE TABLE catalog_org_visibility (
    org_id     TEXT NOT NULL,
    item_id    TEXT NOT NULL REFERENCES catalog_items(id) ON DELETE CASCADE,
    visible    BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, item_id)
);

-- +goose Down
DROP TABLE IF EXISTS catalog_org_visibility;
