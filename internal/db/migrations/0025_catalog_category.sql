-- +goose Up
-- Catalog faceted filtering: persist the package.yaml category so the
-- browse API can filter/facet on it (ADR-0009).
ALTER TABLE catalog_items ADD COLUMN category TEXT NOT NULL DEFAULT '';

CREATE INDEX catalog_items_category_idx ON catalog_items (category) WHERE category <> '';

-- +goose Down
DROP INDEX IF EXISTS catalog_items_category_idx;
ALTER TABLE catalog_items DROP COLUMN IF EXISTS category;
