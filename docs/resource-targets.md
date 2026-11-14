# Org resource targets

Org resource targets are secret-free authorization and configuration overlays over existing Inari inventory. They are not a second resource catalog: a target points to an existing cluster (future providers may point to other inventory kinds), while the cluster registry, `tenant_git_repos`, `cluster_addons`, and discovered capabilities remain authoritative.

The first providers are:

| Capability | Backing resource | Team action | Purpose |
| --- | --- | --- | --- |
| `deployment.cluster` | cluster | `use` | Existing orchestrator deploy and instance-mutation authorization |
| `monitoring.grafana` | cluster plus concrete addon/Helm-release evidence | `provision` | Select an eligible Grafana target for a later observability DeploymentPlan |

Both providers use the same target table, grants, resolver, readiness model, and REST API.

## Security and grant model

`resourcetargets.manage` is an org permission in the built-in admin and operator roles. Managers can register, configure, disable, delete, and grant targets. Manager permission implies target visibility/use/provision, but never bypasses provider policy or an approval requirement.

A team has at most one grant per target:

- `view`: the target can appear in a view list and be read.
- `use`: includes view and permits a use submission, such as a deployment.
- `provision`: includes view and permits a provision submission, such as a later observability companion.

Provider-specific actions prevent a deployment `use` grant from becoming a Grafana `provision` grant. Existing operation permissions still apply: for example, a deployment also requires org `deployments.create`. Approval resume independently revalidates both that org permission and the target `use` grant as the original requester before any Git or agent side effect; either revocation produces a terminal `deploy.target_denied` audit outcome.

List uses uncached OpenFGA `ListObjects`; get/resolve uses `Check`. A current-database membership/grant fence then narrows non-manager access. It can only deny, never grant. Consequently, a deleted or downgraded grant denies immediately even if an older cached OpenFGA allow still exists. New or upgraded grants fail closed until the `resource-target-authz` outbox consumer synchronizes them. Cache failures use the existing fail-open-to-OpenFGA path; an OpenFGA outage fails closed.

List authorization and backing projections are evaluated in bounded org-wide batches (one relation query per action and one grant-fence query per action), with manager grants loaded in one org query rather than per target. Deployment-only lists do not load Grafana discovery or approver teams. Action-specific resolve checks only the requested grant and does not recompute every provider action.

Every resolve reloads the target and backing projections. There is no descriptor, readiness, or binding cache. `expectedRevision` detects preflight/submit skew. A later DeploymentPlan must store the selected target ID and revision and call `Resolve` again at submit. Target grants do not constitute approval; provider-returned approval policy must be enforced by that plan before rendering.

## REST contract

All routes are registered in `internal/restsurface.Register` and therefore appear identically in live serving and `make export-openapi`.

| Method and path under `/api/v1/tenants/{org}` | Access |
| --- | --- |
| `GET /resource-target-providers` | Org member; provider config/selection JSON Schemas and UI hints |
| `GET /resource-targets` | Entitlement-filtered; optional `capability`, `action=view|use|provision`, `resourceKind`, `resourceId`, `includeUnavailable` |
| `POST /resource-targets` | Manager; adopt an existing resource |
| `GET /resource-targets/{id}` | View grant; managers also receive all grants |
| `PATCH /resource-targets/{id}` | Manager; requires current `revision` |
| `DELETE /resource-targets/{id}` | Manager; deletes only the overlay and grants |
| `PUT /resource-targets/{id}/grants/{teamId}` | Manager; body `{ "relation": "view|use|provision" }` |
| `DELETE /resource-targets/{id}/grants/{teamId}` | Manager; revoke, idempotently |

There is no public arbitrary-resolve endpoint. Consumers list targets and submit the target ID to the owning service, which performs the authoritative server-side resolve.

A target descriptor includes `resourceRef`, `capabilities`, normalized `config`, computed `binding`, `readiness`, `effectiveActions`, `enabled`, `isDefault`, and `revision`. The binding is derived from the current cluster baseline and tenant Git repository. Clients cannot replace the cluster, repo, renderer, addon evidence, or URL in a target selection.

For `action=view`, unavailable targets are hidden unless `includeUnavailable=true`; use/provision lists always omit unavailable targets. Managers can inspect disabled/unavailable targets. Typical errors are 403 for grant denial, 404 for unknown/cross-org targets, 409 for conflicts/stale revisions/unavailable bindings, 422 for provider validation, and 503 for an authorization backend outage.

## Provider contract and UI schema

A provider implements:

1. `Describe`: capability, accepted resource kinds, supported actions, config and selection JSON Schemas, UI hints, and default support.
2. `NormalizeConfig`: strict unknown-field rejection and canonical non-secret config.
3. `ValidateRegistration`: backing-resource, evidence, team, baseline, and policy validation.
4. `Resolve`: computed binding and projection-based readiness.
5. `ValidateSelection`: type-specific user choices and approval requirements.

Providers receive no HTTP client, secret loader, kubeconfig, or cluster connection. Readiness here means target eligibility only; it does not prove that an application's dashboards or rules are provisioned.

### `deployment.cluster`

Config and selection are empty objects. Active clusters are ready; degraded clusters remain selectable with a warning, matching existing orchestrator behavior. Other lifecycle states are unavailable. The resolved binding uses the cluster's bound platform baseline, falling back to the org default. Existing registered team-repo selection and repo-write checks remain independent and enforced.

### `monitoring.grafana`

Admin config has this shape:

```json
{
  "baseUrl": "https://grafana.example",
  "evaluation": "central",
  "folderPrefixes": ["acme"],
  "datasources": [{ "name": "metrics", "type": "prometheus" }],
  "approval": { "required": true, "approverTeamIds": ["<same-org-team-uuid>"] },
  "evidence": { "addonId": "<concrete-cluster-addon-id>" }
}
```

Rules:

- `baseUrl` is absolute HTTPS with no userinfo, query, or fragment.
- `evaluation` is `central` or `local`.
- Folder prefixes and datasources are explicit non-empty allowlists.
- Required approval names at least one same-org approver team.
- The addon must be a concrete (not fleet `*`) `cluster_addons` row on the target cluster. Its discovered release name/namespace must match a live `helm-release` capability whose status is `deployed`.
- A provision-eligible target needs a current same-org platform baseline binding.

The later plan selection contains only `folder`, `datasource`, and `evaluation`. Evaluation must match target policy, and folder/datasource must be allowed. Unknown fields such as `baseUrl`, `clusterId`, `repoId`, credentials, or renderer settings are rejected.

The hub never calls Grafana. No readiness result fabricates a dashboard link. Target-side folder/dashboard/datasource/access verification and deep-link gating belong to the later observability/verification tasks.

## Audit and concurrency

Target and grant mutations write the DB projection, audit event, and outbox event in one transaction. Audit metadata identifies the target/resource/team, old/new grant, and revision; raw config and URLs are not logged. `deploy.target_denied` records a terminal approval-resume denial.

`PATCH` uses a conditional revision update. Unique constraints reject duplicate resource adoption, duplicate provider names, and competing defaults. Default promotion/demotion occurs in a transaction. Authorization sync rereads current DB state for every event, so replay or out-of-order delivery cannot restore an older grant. Team deletion and tenant freeze/restore carry exact target-grant snapshots.

Disabling is allowed even when the cluster or evidence is already stale. Deleting a target does not delete its cluster, repository, addon, instances, or other running resources.

## Migration and rollout

Migration `0040_resource_targets.sql` creates `resource_targets` and `resource_target_grants`, adds `resourcetargets.manage` to existing admin/operator roles, and backfills deployment targets for existing non-revoked/non-decommissioned clusters. Existing teams receive `use` when their current role contains `deployments.create`, otherwise `view` when it contains `tenant.read`. Custom roles are included. No Grafana target is invented.

Rollout procedure:

1. Back up PostgreSQL and roll out the migration/new server together.
2. The server runs an initial target authz sync before accepting traffic. A sync failure aborts startup rather than silently dropping backfilled grants.
3. Verify backfilled target/grant counts and one deployment per representative built-in/custom role.
4. Register Grafana only after its cluster, concrete addon/release evidence, and baseline binding exist. Add explicit team `provision` grants and optionally one provider default.
5. Monitor the `resource-target-authz` durable consumer, outbox dead letters, OpenFGA failures, PEP cache invalidation metrics, and target unavailable reasons.

For temporary removal, disable rather than delete. For revocation, delete the team grant; non-manager resolution is fenced immediately while OpenFGA converges. New allows are asynchronous and should be verified before handing the target to a team.

## Rollback

Roll back the server binary without running the SQL down migration first. Additive generated API clients can remain deployed. If database rollback is required, stop the new server and preserve any needed overlay configuration, then run migration 0040 down. It drops only target overlays/grants and the new role permission; backing resources and workloads remain. Do not run the down migration while the new server is active.

## Explicit boundary

This feature does not render observability companions, write central baselines, call Grafana, add embedded panels, or change UI/CLI. Those remain separately gated work. In particular, sibling renderer/multi-repo Phase 3 must be confirmed before any companion rendering or deployed central/local provisioning.
