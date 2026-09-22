-- +goose Up
-- UI extension registry (plan §5.8/§5.9): one extension row may carry a UI
-- descriptor (Module Federation remote) alongside or instead of a backend
-- sidecar — mirroring extension.yaml `spec.kinds: [backend, ui]`. The
-- descriptor holds the remoteEntry source, slot declarations, and enable
-- flag; the control plane serves remoteEntry.js itself.

ALTER TABLE extensions ADD COLUMN ui JSONB;

-- +goose Down
ALTER TABLE extensions DROP COLUMN IF EXISTS ui;
