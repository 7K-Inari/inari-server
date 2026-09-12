-- +goose Up
-- Poison-event hardening for the outbox dispatcher: track per-row delivery
-- attempts and the last handler error so a permanently failing event can be
-- dead-lettered (marked published with the error recorded) instead of
-- hot-looping every poll interval and head-of-line blocking the queue.
ALTER TABLE outbox ADD COLUMN attempts INT NOT NULL DEFAULT 0;
ALTER TABLE outbox ADD COLUMN last_error TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE outbox DROP COLUMN last_error;
ALTER TABLE outbox DROP COLUMN attempts;
