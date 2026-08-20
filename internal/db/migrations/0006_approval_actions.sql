-- +goose Up
-- Generic lifecycle approval actions (plan §5.11/§5.12): approval requests
-- for non-catalog operations (tenant zone vend/decommission). Empty action
-- = catalog deploy gate (existing behavior).
ALTER TABLE approval_requests ADD COLUMN action TEXT NOT NULL DEFAULT '';

-- Lifecycle approvals have no catalog item: item_id becomes nullable
-- (NULL = lifecycle request); the FK is re-added and still permits NULLs.
ALTER TABLE approval_requests ALTER COLUMN item_id DROP NOT NULL;
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_item_id_fkey;
ALTER TABLE approval_requests
    ADD CONSTRAINT approval_requests_item_id_fkey
    FOREIGN KEY (item_id) REFERENCES catalog_items(id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE approval_requests DROP CONSTRAINT approval_requests_item_id_fkey;
ALTER TABLE approval_requests
    ADD CONSTRAINT approval_requests_item_id_fkey
    FOREIGN KEY (item_id) REFERENCES catalog_items(id) ON DELETE CASCADE;
DELETE FROM approval_requests WHERE item_id IS NULL;
ALTER TABLE approval_requests ALTER COLUMN item_id SET NOT NULL;
ALTER TABLE approval_requests DROP COLUMN IF EXISTS action;
