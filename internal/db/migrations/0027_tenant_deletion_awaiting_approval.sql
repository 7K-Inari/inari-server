-- +goose Up
-- Approval-gated tenant decommission (run 423ffd13 finding): the deletion
-- row is created in awaiting_approval and only transitions to deleting when
-- the lifecycle approval is granted; the startup resume scan must never
-- execute an undecided teardown.
ALTER TABLE tenant_deletions DROP CONSTRAINT tenant_deletions_state_check;
ALTER TABLE tenant_deletions ADD CONSTRAINT tenant_deletions_state_check
    CHECK (state IN ('awaiting_approval','deleting','delete_failed'));

-- +goose Down
-- Rows still awaiting approval have no teardown progress; deny-path
-- semantics (restore) apply to them, so mapping them back to deleting is
-- safe for a rollback.
UPDATE tenant_deletions SET state = 'deleting' WHERE state = 'awaiting_approval';
ALTER TABLE tenant_deletions DROP CONSTRAINT tenant_deletions_state_check;
ALTER TABLE tenant_deletions ADD CONSTRAINT tenant_deletions_state_check
    CHECK (state IN ('deleting','delete_failed'));
