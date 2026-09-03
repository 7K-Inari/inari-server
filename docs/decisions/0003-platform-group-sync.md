# ADR 0003: Platform admin group → OpenFGA tuple sync

## Status
Accepted (M1.W2)

## Context
All global permissions live in OpenFGA; Keycloak is used only for OIDC
authentication and group attribution. Membership of the realm group
`platform-admins` (configurable via `INARI_PLATFORM_ADMIN_GROUP`) must become
`platform:inari org_creator user:<id>` tuples, and removals must delete them.
`POST /api/v1/tenants` enforces `Check(user, org_creator, platform:inari)` and
`GET /api/v1/me/permissions` surfaces the same check to clients.

## Decision
A **periodic reconciler** (`authz.PlatformGroupSync`) runs inside the server
every `INARI_PLATFORM_GROUP_SYNC_INTERVAL` (default 30s). Each pass lists the
Keycloak group's members (Admin REST), reads current `org_creator` tuples via
the FGA Read API, and writes/deletes the set difference. The reconciler is the
**single writer** of `org_creator` tuples on `platform:inari`; `superuser`
tuples are out of scope.

## Alternatives considered
- **On-login reconciliation hook** (compare the JWT `groups` claim against the
  tuple on each authenticated request): requires a group-membership token
  mapper in the realm (not present today), puts FGA calls on the auth hot
  path, and only deletes tuples for users who authenticate again — users who
  never return keep stale grants.

## Consequences
- **Consistency window**: a grant/revoke in Keycloak takes effect within one
  sync interval (≤30s default).
- The admin service account needs group-read permission on the realm (it
  already manages users/groups for tenancy).
- Reconciliation is idempotent and self-healing: FGA state is derived from
  Keycloak group membership on every pass, never the other way around.
- The dev realm (`deploy/dev/keycloak/inari-realm.json`) ships the group with
  `dev-admin` as a member; `e2e/golden-path.sh` additionally provisions it
  imperatively (GAP(kc-platform-group)) and polls the FGA check before
  creating a tenant.
