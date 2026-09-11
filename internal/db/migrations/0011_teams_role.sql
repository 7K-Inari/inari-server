-- +goose Up
-- Custom teams carry the org role they grant (default teams seeded before
-- this migration default to 'viewer' and are corrected below).
ALTER TABLE teams ADD COLUMN role membership_role NOT NULL DEFAULT 'viewer';

UPDATE teams SET role = 'platform-engineer' WHERE name = 'platform-team';
UPDATE teams SET role = 'developer' WHERE name = 'developers';

-- +goose Down
ALTER TABLE teams DROP COLUMN role;
