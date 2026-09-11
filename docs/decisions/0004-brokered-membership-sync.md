# ADR 0004: Brokered org membership syncs to OpenFGA via reconciliation

## Status
Accepted (M6.W7)

## Context
Tenants can broker an external OIDC IdP into their Keycloak Organization
(M6.W6, Settings design §3.3). Users authenticating through a brokered IdP
are auto-onboarded as org **managed members** and land directly in Keycloak
org-team groups: the Hardcoded Group mapper puts everyone in
`tenant-<slug>/members`, and Advanced Claim to Group mappers
(`claimMapping.groups`) add them to `tenant-<slug>/<team>` groups.

These users never pass through the inline invite path
(`internal/tenancy/members.go`: Keycloak group join + membership row +
outbox event → tuple writer), so without further machinery **no OpenFGA
tuples are ever written for them**. Conversely, managed members can
disappear from Keycloak when unlinked or removed at the IdP; tuples left
behind are an authz leak. The M6.W5 spike (Q2, recommendation 5)
established: **invite flow = inline writes, brokered flow = reconcile.**

## Decision
A second periodic reconciler, `authz.OrgTeamSync`, generalizes the ADR-0003
pattern to every server-owned tenant team group:

- Team groups are enumerated from the DB `teams` projection (each row
  carries its `keycloak_group_path`, always `tenant-<slug>/<team>` — only
  server-owned groups are ever reconciled; the platform admin group stays
  exclusively with `PlatformGroupSync` per ADR 0003).
- Per group, Keycloak membership (`ListGroupMembers`) is diffed against FGA
  `team:<id>#member` tuples and the delta applied **in both directions**:
  tuples are written for members missing in FGA and deleted for principals
  no longer in the Keycloak group.
- Both reconcilers share one `reconcileGroup` diff helper; Keycloak group
  membership is the source of truth, FGA state is derived from it on every
  pass, never the reverse.
- The Hardcoded mapper target `tenant-<slug>/members` has no inline writer
  at all, so `CreateBrokeredIdP` materializes a viewer-role `members` team
  (via the existing lazy `ensureTeam`), giving the reconciler a team object
  to converge tuples on.
- Convergence window: one `INARI_ORG_GROUP_SYNC_INTERVAL` (default 30s)
  after a brokered login, group-mapping change, unlink, or removal. A
  failing group is logged and skipped so one tenant cannot starve the
  others; the next tick retries.

`team#member` tuples have two writers (the outbox tuple writer for invited
members, this reconciler for everyone). That is safe because both derive
from the same source of truth — Keycloak group membership — so
interleavings converge within one interval (the same accepted trade-off as
ADR 0003).

## Alternatives considered
- **Enumerate groups from Keycloak** (`GET /groups` under `tenant-*`)
  instead of the DB projection: KC group paths carry no Inari team IDs, so
  building `team:<id>` objects requires the DB anyway — extra KC surface
  for no benefit.
- **Token-claim hot path** (map a groups claim and check/write tuples on
  each authenticated request): needs a group-membership token mapper, puts
  FGA calls on the auth hot path, and never revokes users who stop logging
  in. Rejected by the M6.W5 spike.
- **Replaying brokered logins through the invite path**: managed members
  appear at login with no server-side hook in the brokering flow; there is
  no inline point to hook into.

## Consequences
- Brokered members gain org access (viewer via `members`, plus any
  claim-mapped team roles) within ≤ one sync interval of first login.
- Revocation (IdP unlink, managed-member removal) propagates within the
  same window; no stale `team#member` tuples persist for deleted users.
- The admin service account needs group-read on every `tenant-*` group
  (already required for tenancy group management).
- Membership **DB rows** remain invite-projection only; console member
  lists are unaffected. FGA tuples are the authz-relevant state.
- SAML brokering (W8) reuses this reconciler unchanged — its mappers land
  users in the same Keycloak groups.
