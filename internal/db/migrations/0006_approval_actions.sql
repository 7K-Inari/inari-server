-- +goose Up
-- Generic lifecycle approval actions (plan §5.11/§5.12): approval requests
-- for non-catalog operations (tenant zone vend/decommission). Empty action
-- = catalog deploy gate (existing behavior).
ALTER TABLE approval_requests ADD COLUMN action TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE approval_requests DROP COLUMN IF EXISTS action;
