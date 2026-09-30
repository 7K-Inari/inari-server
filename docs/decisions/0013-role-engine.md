# ADR-0013: Role engine — customizable org roles over a static permission catalog

Status: accepted (M1W2, supersedes the org-role part of the fixed 4-role hierarchy)

## Context

Org authorization was four fixed hierarchical roles (org-admin ⊇ platform-engineer ⊇
developer ⊇ viewer), encoded in the `membership_role` enum, the OpenFGA
`admin/platform_engineer/developer/viewer` relations, and the four anchor ClusterRoles
`tenant-<slug>-{admin,operator,editor,viewer}`. Tenant admins need to define their own
roles (e.g. "deployer", "people-ops") without platform changes.

## Decision

**Static permission catalog + dynamic DB roles.**

- A server-owned, static catalog of 19 permission slugs
  (`internal/authz/permissions.go`: `tenant.read`, `tenant.settings.write`,
  `tenant.members.manage`, `tenant.teams.manage`, `tenant.rbac.manage`,
  `tenant.identity.manage`, `tenant.notifications.manage`, `tenant.admin`,
  `clusters.register`, `cloudaccounts.manage`, `zones.manage`, `fleet.manage`,
  `policies.manage`, `secretstores.manage`, `extensions.manage`, `extensions.invoke`,
  `catalog.manage`, `deployments.create`, `approvals.manage`) is the only thing the
  OpenFGA model encodes: one `organization` relation per slug (dots → underscores),
  each granted directly via `[team#member]` usersets.
- `roles` is a DB table (`id, org_id, name, display_name, description, builtin,
  permissions jsonb`). Roles are pure DB state — role CRUD never rewrites the FGA
  model. Four built-ins (`admin`, `operator`, `editor`, `viewer`) are seeded per
  tenant with bundles mirroring the retired hierarchy; their names double as the
  ClusterRole suffixes, preserving the pinned `tenant-<slug>-{admin,operator,editor,viewer}`
  contract.
- `teams.role` / `memberships.role` (enum) become `role_id` FKs (migration 0029,
  backfilled from the built-ins; memberships PK becomes `(user_id, org_id, role_id)`).

**Built-ins: editable, deletion-protected, guardrail-enforced.** Built-in roles are
never deletable and never renamable, but their permission bundles are editable. Every
mutation point — role PATCH, role DELETE, `PUT rbac/mappings`, team DELETE —
re-checks inside its TX that ≥1 team resolves to a role containing `tenant.admin`;
violations roll back and answer 409 (a tenant can never lock itself out). Custom
roles bound to teams cannot be deleted (409, remap first).

**Pre-V1 clean OpenFGA swap — no dual-write, no model migration.** `model.fga` and
`ModelV1` are replaced in one step; the four hierarchical relations are deleted
outright. Tuples are rebuilt deterministically, not migrated: the new `OrgRoleSync`
reconciler (`internal/authz/rolesync.go`) diffs the DB teams/roles projection against
actual tuples and converges both directions — it runs once synchronously at startup
(before the server accepts traffic, so the post-swap rebuild completes before PEP
checks are served) and then on the org-group-sync interval for drift self-heal. A
best-effort startup sweep deletes tuples under the retired relations, tolerating
"relation not found". Child types keep their parent chains, derived from
domain-matched permission relations (e.g. `cluster.operator = clusters_register from
parent`, `policy_pack.operator = policies_manage from parent`,
`extension.invoke = extensions_invoke from parent`; all `viewer` relations =
`tenant_read from parent`). Only `extension.invoke` has a production call site; the
other child relations are model-completeness only. The outbox TupleWriter writes one
userset tuple per (team, permission); payload snapshots (`TeamSeed.Permissions`,
`TeamRoleChange.{Old,New}Permissions`, `RolePayload.{Old,New}Permissions + TeamIDs`)
keep consumers DB-free. Every write path still goes through `authz.InvalidatingStore`
(generation bump) so the 2s PEP cache never serves stale grants.

**rbacmaterialize renders one ClusterRole per org role.** Each permission maps to a
k8s rule-fragment tier (admin/operator/editor/viewer, or none for tenant-plane-only
permissions); a role's ClusterRole renders the highest fragment its bundle contributes
(byte-pinned so the four built-ins render exactly the retired anchor rules). Bindings
stay role-qualified (`tenant-<slug>-<team>-<role.Name>`), so a mapping flip renders a
new binding and ArgoCD prunes the stale one (roleRef immutability carries over).
The RBAC matrix API synthesizes ClusterRole names from the roles table
(`tenant-<slug>-<role.Name>`).

**PEP checks move from role relations to permission slugs** (~150 call sites). The
mapping is semantics-preserving by default (`viewer`→`tenant.read`,
`platform_engineer`→the domain's infrastructure permission, `developer`→
`deployments.create`/`catalog.manage`/`approvals.manage`, `admin`→the tenant-domain
management slug). Flagged judgment calls:

- tenant deletion → `tenant.admin` (also the guardrail anchor)
- catalog-item delete → `tenant.admin` (was admin-gated)
- policy-pack delete → `tenant.admin` (was admin-gated; CRUD/assign is `policies.manage`)
- policy evaluation → `deployments.create` (was developer-gated)
- git-config PUT → `tenant.settings.write` (narrows: was platform-engineer)
- cluster registration-token revoke → `clusters.register` (widens: was admin)
- member role grant (`PUT members/{subject}`) → `tenant.rbac.manage` (stays admin-only;
  `tenant.members.manage` would allow privilege self-escalation)
- approvals platform-admin policy + lifecycle-approver floor → `clusters.register`,
  the platform-operations floor held by exactly the admin and operator built-in
  bundles. The approvals `RoleResolver` seam becomes a DB-backed `PermissionResolver`
  (memberships → roles projection), which survives the tenant-freeze FGA tuple sweep
  (issue #74).

**API contract changes (pre-V1 clean break, coordinated with inari-ui M1W2):**

- `GET/POST /tenants/{org}/roles`, `GET/PATCH/DELETE .../roles/{role}`,
  `GET .../permissions/catalog`.
- `PUT .../rbac/mappings` body is `{mappings: [{team, roleId}]}`; team create and
  member-role PUT take `roleId` (ID or built-in name).
- `GET /me/permissions`: `orgRoles` (single effective role) is replaced by `roles`
  (set of role names per org from the DB projection — custom roles have no total
  order); the `tenants` capability flags are unchanged in shape and now computed from
  four permission checks.
- Org member list returns `roles` (set) instead of a single "highest" role.
- Scaffold `bindRbac.role` accepts the built-in names (`admin/operator/editor/viewer`)
  and maps the retired enum values for template compatibility.

## Consequences

- The FGA model is static: role CRUD is DB-only plus tuple rewrites, so no
  authorization-model pinning dance and no cache-invalidation storms on role edits.
- Between model swap and the first `OrgRoleSync` pass, org-level checks fail closed;
  the synchronous startup pass bounds that window to boot time.
- A role edit rewrites tuples only for teams bound to it (payload-carried TeamIDs);
  `OrgRoleSync` converges any drift from missed events.
- The memberships PK change preserves the M1W1 never-downgrade/invite-conflict
  semantics (role_id replaces role in the conflict key).
- inari-docs plan §5.4 + a platform-plan ADR update is a follow-up (inari-docs was
  not attached to this change's workspace).

## Alternatives considered

- **Per-role FGA relations (dynamic model rewrite on role CRUD)** — rejected:
  model rewrite + authorization_model_id pinning per role edit, cache-invalidation
  storms; the pre-V1 clean-swap decision explicitly avoids it.
- **DB-only permission checks (drop FGA for org roles)** — rejected: breaks the
  §5.4 fine-PEP architecture (OpenFGA behind `Authorizer`, ADR-0010 cached hot path).
