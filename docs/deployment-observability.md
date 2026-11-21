# Deployment-time observability

DeploymentPlans normalize catalog packages, exact-digest direct OCI Helm charts, and declared deployment-capable component templates into one server-authoritative intent. Pure scaffolds and `gitops-repo` templates never provision observability.

## API

Under `/api/v1/tenants/{org}`:

- `POST /deployment-plans/preflight` performs read-only normalization/admission and returns exact app/pack pins, assets, compatible packs, entitlement-filtered application/monitoring targets, and renderer-gate state. Tenant pack pins are authoritative; otherwise only stable candidates are offered, with the effective version first. A monitoring target appears only after provider selection resolves and an exact pack is visible/admitted in that target environment.
- `POST /deployment-plans` requires an idempotency key and revalidates the application target, catalog visibility, monitoring provision grant, target revision, provider folder/datasource/evaluation selection, approval policy, app/pack compatibility, and exact digests. Malformed plan/source/spec/team/chart input returns a typed 4xx response; reviewed digest or approval drift conflicts rather than executing different bytes.
- `GET /deployment-plans/{id}` returns plan and companion state.
- `GET /instances/{id}/observability` supports later provisioning state and readiness-gated links.

There is no public arbitrary-target resolver or verification-result endpoint. Target administration remains under the generic resource-target API.

## Rendering and duplicate prevention

Inari-managed charts receive final server-owned values `observability.enabled=false` and `observability.rules.enabled=false`; attempting to force either true is rejected. Standalone Helm users retain control of those values.

Central companion intent selects dashboards plus central rules. Local intent selects dashboards plus local rules. Only packs annotated with `inari.observability-pack/v2` are compatible because that contract makes both evaluation booleans effective. The server rejects older ambiguous packs rather than emitting duplicate or cross-environment rules.

The application starts through the existing catalog/template execution path. Application approval resume reruns the common plan's grant, target, compatibility, and exact-pin validation without executing a duplicate app, then links only the real orchestrator result back to the plan. Template execution requires the reviewed artifact digest both before run persistence and when the run is linked. A provision request while the sibling renderer gate is closed records `blocked_external_gate` without creating a companion approval, Git write, ArgoCD registration, companion instance, verification run, or automatic later resume. No legacy single-repo adapter exists.

## Readiness and links

KRO, ArgoCD, and application health do not prove Grafana readiness. A real companion must reach verification and receive a current read-only target-side result for folder, dashboards, datasource, and selected rules. The result must match companion generation, target revision/cluster, app source revision/digest, pack digest, capability digest, and approved suite/run identity. The suite profile is the generic environment grant's actual `ci`, `stage`, or `prod` profile; no synthetic observability profile or Grafana identity/folder-access evidence is accepted. The existing outbound verification report reaches the deployment-plan consumer in-process after generic policy/grant/run binding.

The hub never calls Grafana. Links are derived only for a `ready` companion with unexpired matching evidence and a caller who retains the target view grant. Every status read also compares the live inventory application version, digest, cluster, ownership, namespace, repo, and semantic spec with the reviewed plan (including the server-owned chart overlay). Upgrade or edit drift produces `stale` and removes links immediately; expiry, evidence drift, view revocation, and target failure produce `expired`, `stale`, `revoked`, or `unavailable`, never a READY/no-links ambiguity. URLs use the resolved HTTPS target base URL, verified dashboard UID/slug, and declared link variables. Pending, skipped, failed, stale, expired, revoked, or cancelled states return no links. The UI and CLI must not construct their own Grafana URLs.

## Migration and rollback

Migration `0043_deployment_observability.sql` adds deployment plans, linked companions, and verification receipts. It is intentionally ordered after the coordinated plugin migration `0042`; rebase/renumber if main advances first. The migration contains no companion rendering or production configuration.

Back up PostgreSQL before rollout. For binary rollback, run the older server before considering the down migration. The down migration drops only these new tables; stop the new server first. Any future real companion desired state requires separate approved cleanup and is never automatically deleted.

## Operations

Monitor failed preflight/admission and target authorization errors, plans stuck in `waiting_for_app`, and verification failures/expiry. Register Grafana targets only with current cluster and either Helm-addon or trusted KRO-instance evidence, a same-org platform baseline, explicit folder/datasource policy, approver teams, and team provision grants. Production central rendering and deployed verification remain gated on independent sibling Phase 3 confirmation.
