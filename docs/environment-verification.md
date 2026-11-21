# Self-service environment verification

## Status and hard execution boundary

This module provides signed-suite admission, platform/team policy, deterministic run identity and dedupe, promotion evidence gates, notification/history projections, and authenticated outbound-agent report ingestion. **Argo Workflows is optional and is never installed by verification.**

Concrete `WorkflowTemplate`, PostSync `Workflow`, standalone `Workflow`, `CronWorkflow`, synchronization resources, associated Git writes, and deployed runs are intentionally not wired. They remain stopped until independent confirmation of sibling `8f8c472a` Phase 3. There is no environment-variable bypass or legacy single-repository adapter. Saving a closed-gate policy does not queue stale work; manual execution returns `external_gate_closed` and creates no run row.

## Trust and eligibility

Platform operators import a complete `artifactadmission.ArtifactDescriptor` through the platform-only suite preview/create APIs. The descriptor is untrusted input until `catalog.Service.AdmitSmokeSuite` resolves the configured source policy and calls the existing artifact verifier. The verifier checks exact repository@digest, source namespace, signature/publisher/workflow, SourceSHA, SLSA provenance, and signed test evidence for official/reviewed sources. The target cluster never fetches the suite and receives no registry credential.

A real stage/prod binding requires all of:

1. Exact admitted application item/version/artifact digest and signed `admission.runtime.suiteDigest` with `result=passed`.
2. Exact approved suite OCI digest, target/component/version, and parameter contract.
3. Exact unexpired, unrevoked environment grant for suite digest + profile.
4. Current deployment target `use` entitlement and target/environment revision.
5. Signed evidence with `evidenceScope=application`, `appEvidenceEligible=true`, `fixtureOnly=false`, and the requested profile in `executableProfiles`.

`fixtureOnly=true`, fixture scope, explicit application ineligibility, partial eligibility, and missing eligibility fail closed. Legacy v1.0.0 metadata is never interpreted as eligible. The only legacy exception is an exact signed, artifact-bound digest with an exact signed app Runtime binding and explicit platform development/CI policy; it is non-production/non-evidence, produces `legacy_eligibility_exception` preview/audit records, and cannot satisfy observability readiness or promotion.

## Platform guardrails

An `EnvironmentVerificationPolicy` is bound to a deployment `ResourceTarget` and its backing cluster environment. Development/staging accept `stage`; production accepts `prod`; `ci` is not a real-instance profile. A `SuiteGrant` fixes:

- Exact suite release/digest/profile and optional app item/version range.
- Preapproved non-default ServiceAccount and expected RBAC policy digest.
- Finite allowed RBAC rules; wildcards, RBAC administration, impersonation, bind, and escalate are denied. Suite `rbacRequirements` must be a subset and never create Roles/RoleBindings.
- Preapproved egress policy reference. Teams cannot submit CIDRs, proxy URLs, NetworkPolicies, or credentials.
- Side effects, timeout, active/pending concurrency, retention, result size, notification/approver policy, fixture namespace, cleanup, and grant expiry.
- Optional HTTPS Argo Workflows UI base URL for read-time external links.

Production defaults to readOnly. Synthetic/mutating grants in every environment require isolated fixtures, exit cleanup, named per-run approval, and a change window. Synthetic and mutating automatic/PostSync execution is denied while per-run approval is required. Production grant creation re-admits the suite and requires fresh signed release evidence within the environment's approval-age limit.

Static signed Workflow validation rejects external template references, mutable images, ServiceAccount/namespace/podSpecPatch/synchronization overrides, hostPath/host namespaces, privilege escalation, resource/apply templates, suite-created RBAC, suspend steps, and unbounded parallelism/retries/output.

## Team policy and triggers

`VerificationPolicy` supports onRevisionChange (default on), observed onSync/manual/cron, timeout, active/pending concurrency, Workflow/result retention, existing notification endpoint IDs, addon-absence behavior, and failure action. Preview revalidates org, target, app, suite, grant, SemVer compatibility, RBAC, egress, side effects, and policy revision before returning effective read-only guardrails. Save performs the same preview and optimistic revision check. An empty `binding.specDigest` requests a fresh digest from the server's exact stored spec JSON; the normalized preview/save binding contains the resulting immutable digest.

The run key is SHA-256 over instance UID + appRevision + suite digest + canonical trigger. The public run ID is stable lowercase base32. App revision binds instance UID, item/version/digest, canonical spec digest, generation, and desired commit. Manual idempotency keys distinguish deliberate repeats; explicit retry uses the same run ID and a new attempt. Cron derives its scheduled instant from Argo's deterministic child name. Health-only updates do not trigger revision runs; onSync requires a new successful operation for the exact current deployed revision.

ArgoCD health/sync remains on `ResourceInstance`; verification status is independent. Addon absence `skip` is not passed and cannot satisfy required evidence. Failure actions are notify/pausePromotion/blockPromotion only. **Verification never invokes automatic promotion or rollback.**

## Reports, notifications, and links

The agent watches only `argoproj.io/v1alpha1` Workflow objects labelled `inari.dev/verification=true` with read-only RBAC. It maps strict annotations and bounded `inari-verification-outcome` output to `EVENT_TYPE_VERIFICATION_REPORT=16` on the existing outbound stream. Org/cluster identity comes from the authenticated gateway session. Reports bind run/attempt, app revision/digest, suite/profile, target, policy/grant revisions, Workflow UID/resourceVersion, timestamps, and outcome digest.

A passing generic application report requires a valid `inari.verification.outcome/v1` payload, all checks passing, and unexpired evidence. Missing/malformed evidence fails. Receipts contain only cluster/Workflow/resourceVersion/run/attempt/payload digest. Terminal outcomes are immutable. Raw observability outcomes are forwarded transiently to the sibling's in-process sink; generic verification stores only common state/digest/reference, not a second observability state machine or raw result store.

Notifications use existing Slack/webhook endpoints and the outbox. Only team-selected plus platform-mandatory endpoints receive verification events; endpoint+outbox-ID uniqueness suppresses duplicate delivery. Payloads contain IDs/digests/status and no logs, secrets, specs, or arbitrary URLs.

Run history remains available after link expiry. Workflow/log/artifact links are built at read time from the platform HTTPS Argo UI base URL and bound Workflow identity, only with current target-view entitlement, valid grant, observed Workflow identity, and unexpired retention. Agent-supplied URLs and object-storage credentials are rejected.

## Promotion

A `PromotionPolicy` links a non-production source instance to a production target. Only the latest run matching exact target app digest + required suite digest + profile can authorize. A later failure or expired/stale evidence blocks. `orchestrator.applyWithEvent` calls the predicate for upgrades and approval resume, preventing direct `/upgrade` bypass; explicit same-version edits and user-initiated rollback are not automatic promotion. The `/promote` API is always an explicit reviewed operation.

## Persistence and operations

Migration `0044_environment_verification.sql` follows plugin `0042` and observability `0043`; renumber if main advances. It adds immutable instance UID/observed sync fields, suite/environment/grant/policy/run/attempt/receipt/promotion tables, and notification outbox dedupe. Raw target credentials, registry credentials, pod logs, and secrets are never stored.

Un-gated verification evidence consists of unit tests, PostgreSQL integration tests, generated OpenAPI/protobuf checks, agent fake-dynamic-client tests, and transport fixtures. These are not deployed stage/prod evidence. After the external gate opens, collect real render PR/commit, Workflow UID/run ID/attempt, app/suite digests, agent report receipts, RBAC/egress denial, reconnect/dedupe/concurrency/retention, and no-rollback evidence on stage first. Production additionally requires owner approval, named approvers, and a change window.
