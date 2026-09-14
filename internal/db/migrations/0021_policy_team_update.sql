-- +goose Up
-- Policy update hardening + team display names (ADR-0007):
-- policies get an org-scoped name uniqueness guarantee so PUT
-- /tenants/{org}/policies/{id} can safely rename (409 on conflict);
-- teams get a mutable display_name while name and keycloak_group_path
-- stay immutable.
CREATE UNIQUE INDEX policies_org_name_key ON policies (COALESCE(org_id, ''), name);

ALTER TABLE teams ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE teams DROP COLUMN display_name;
DROP INDEX policies_org_name_key;
