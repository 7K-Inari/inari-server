-- +goose Up
ALTER TABLE extensions
    ADD COLUMN contracts JSONB,
    ADD COLUMN degraded_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN degraded_detail TEXT NOT NULL DEFAULT '';

ALTER TABLE extensions
    ADD CONSTRAINT extensions_degraded_reason_check
    CHECK (degraded_reason IN ('', 'contract_unsupported', 'handshake_failed', 'identity_mismatch', 'checksum_mismatch', 'process_exited'));

-- +goose Down
ALTER TABLE extensions DROP CONSTRAINT IF EXISTS extensions_degraded_reason_check;
ALTER TABLE extensions
    DROP COLUMN IF EXISTS contracts,
    DROP COLUMN IF EXISTS degraded_reason,
    DROP COLUMN IF EXISTS degraded_detail;
