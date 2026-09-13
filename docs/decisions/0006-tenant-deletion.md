# ADR 0006: Tenant deletion via approval-gated, resumable teardown

## Status
Accepted

## Context
`POST /api/v1/tenants` provisions a full tenant stack (Keycloak Organization
+ groups, DB projection, OpenFGA tuples, base platform resources, and
org-scoped rows in every module), but there was no way to remove a tenant —
the v1 live e2e leaked its test tenant forever. Teardown spans three
systems (PostgreSQL, Keycloak, OpenFGA), so it cannot be one transaction,
and audit history must be retained (plan §7.1 "decommission: archived
audit").

## Decision
`DELETE /api/v1/tenants/{org}` starts an **asynchronous, approval-gated
state machine** rather than a synchronous delete:

- **Lifecycle status.** `organizations.status` (`active|deleting|deleted`,
  migration 0020) freezes the tenant the moment deletion is requested.
  Mutating tenancy routes reject non-active orgs (409), and `OrgTeamSync`
  enumerates only active orgs (`tenancy.Store.ListActiveTeams`) so a
  half-deleted tenant cannot be resurrected by reconcilers. The slug stays
  reserved until the org row is finally removed.
- **Dependency gate.** Without `?force`, the request is rejected (409) with
  the structured blocker list (non-terminal clusters, in-flight instances,
  cloud accounts, non-closed tenant zones); `GET
  /api/v1/tenants/{org}/deletion/dependencies` dry-runs the same check.
  `force: true` revokes non-terminal clusters via the existing
  `clusterregistry.RevokeCluster` flow as a teardown step.
- **Approval gate.** The request opens a platform-admin lifecycle approval
  (`tenant.decommission`, new action in `approvals.ValidLifecycleAction`)
  and returns `202 {approvalId}`. `tenancy.DeletionResumeHandler` consumes
  `approval.decided`: approved → run the teardown; denied → restore
  `active` + audit `tenant.decommission_denied`. Re-requesting while a
  deletion is pending is idempotent (returns the existing approval id).
- **Resumable teardown.** `tenant_deletions` (one row per org) records the
  last completed step; `tenancy.Deleter` runs, in order:
  `revoke_clusters → archive_audit → fga_cleanup → delete_keycloak_org →
  delete_org_row`. Every step is idempotent; a failure flips the row to
  `delete_failed` with `last_error`, and `POST
  /api/v1/tenants/{org}/deletion:retry` or the startup scan
  (`Deleter.ResumePendingDeletions`) resumes at the failed step.
- **Audit retention.** `archive_audit` copies the org's `audit_events` into
  `audit_archive` and purges its outbox rows inside one transaction guarded
  by `SET LOCAL audit.allow_delete='on'` — the append-only trigger was
  amended (0020) to permit deletes only under that transaction-scoped GUC.
  The terminal `tenant.deleted` audit row stays in the live stream under
  the org id string (no FK).
- **Synchronous FGA cleanup.** The tuple snapshot (org role tuples, team
  member tuples, org parent tuples per child object) is enumerated from the
  DB at request time, stored on the deletion row, and retracted by the
  Deleter calling `DeleteTuples` directly (`authz.TuplesForTenantDeletion`)
  — not fire-and-forget via the outbox, because a dead-lettered outbox
  event would leak tuples silently after the org row is gone. The
  `tenant.deleting` outbox event is still emitted so the TupleWriter can do
  a defensive second sweep. `KeycloakAdmin.DeleteOrganization` is already
  404-tolerant, so a manually deleted Keycloak org is treated as done.
- **Final delete.** `DELETE FROM organizations` relies on `ON DELETE
  CASCADE` for most children; tables without an organizations FK
  (`secret_stores`, `scaffold_runs`, `tenant_zones`, `approval_config`) are
  deleted explicitly first.

## Consequences
- Deletion is observable (`GET /api/v1/tenants/{org}` returns `status` and
  deletion progress) and safe to retry; there is no undo past approval.
- In-flight orchestrator runs are not cancelled (no cancel-by-org API);
  documented force caveat.
- Operator-side GC of platform CRs (keycloakrealm/dnszone/tenantnamespace)
  for a deleted tenant remains a follow-up; the server-side desired-state
  rows cascade away with the org.
