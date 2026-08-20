-- +goose Up
-- Cluster lifecycle (plan §5.11): cordon blocks new deploys while workloads
-- keep running; decommissioned is the terminal drained/archived state.
-- New enum values are not used inside this migration, so the transactional
-- ADD VALUE restriction (PG >= 12) does not apply.
ALTER TYPE cluster_state ADD VALUE IF NOT EXISTS 'cordoned';
ALTER TYPE cluster_state ADD VALUE IF NOT EXISTS 'decommissioned';

-- +goose Down
-- PostgreSQL cannot drop enum values; the Down is a no-op by design (the
-- values are inert once no rows reference them).
SELECT 1;
