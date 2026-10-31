# Platform GitOps: per-tenant platform resources

M7.W2. Every tenant gets three base platform resources tracked in the control
plane (`platform_resources` table, status `reconciling` until the platform
reconciler reports back) and rendered as inari-operator `api/v1alpha1` CRs in
the platform GitOps repo — or, with the `platform_resources.gitops_render`
feature flag on, as renderer source descriptors (native manifests, KRO
instance, provider-keycloak claims; see "Render cutover" below):

| Platform resource  | Kind (CR)      | Name          | Desired state                          |
| ------------------ | -------------- | ------------- | -------------------------------------- |
| `keycloak-realm`   | KeycloakRealm  | `<slug>`      | `{"realm":"inari","organization":...}` |
| `dns-zone`         | DNSRecord      | `<slug>`      | `{"mode":"shared-record"}`             |
| `tenant-namespace` | TenantNamespace| `tenant-<slug>`| `{"namespace":"tenant-<slug>"}`       |

The `dns-zone` resource uses the **shared-zone model**: one platform-owned
DNS zone; the tenant's set of DNSRecords lives under it (`shared-record`
mode), no per-tenant hosted zones.

Additionally, each cluster registration upserts a `keycloak-client` resource
(named `cluster-<id>`) tracking the per-cluster OIDC client desired state.

## Repo layout

One directory per tenant in the platform GitOps repo, synced by a single
ArgoCD **ApplicationSet** with a git-directories generator over `tenants/*`:

```
tenants/<slug>/
├── keycloak-realm.yaml
├── dns-record.yaml
└── tenant-namespace.yaml
```

Rationale (vs. one Application per tenant or a central ApplicationSet list):
adding/removing a tenant is a single directory commit/delete; no central file
to conflict on; matches pull-never-push (the operator reconciles from git).

## Control-plane flow

- `tenancy.Service.CreateTenant` — after the DB commit (same pattern as
  Keycloak group creation), calls
  `platformresources.Service.EnsureBaseResources`, which upserts the three
  base rows via `EnsureDesired` (audit + outbox only when new/changed).
- `agentgateway.RegisterCluster` — upserts the `keycloak-client` row after
  the Keycloak client is provisioned, before the registration token is burned
  (retry-safe). With the render cutover on, it renders the provider-keycloak
  `TenantClient` claim into the hub-facing platform repo instead (see below).
- `tenantzonefactory` "wire into Inari" step (`ModuleWiring.WireZone`) —
  re-ensures the base rows (idempotent; safe on zone step retries) and, when
  `INARI_PLATFORM_GITOPS_REPO` is set, renders the CR manifests
  (`platformresources.RenderTenantManifests`) and commits them to the platform
  GitOps repo through the `gitprovider.Provider` seam.
- Startup backfill (`cmd/inari-server/main.go`) — after migrations, ensures
  base rows for all pre-existing tenants (best-effort, logged, idempotent).

Out of scope here: the reconciler status sink (separate task) and resource
deletion on tenant/zone teardown.

## Render cutover (operator sunset Phase 1)

The feature flag `platform_resources.gitops_render` (runtime flag, platform
scope, default **off**) switches the render target from inari-operator CRs to
source descriptors for the source-agnostic renderer (`internal/renderer/`).
This is the dual-run lever while the new render path is validated; the
legacy path above remains the flag-off behavior.

When the flag is **on**, `platformresources` renders into the same
hub-facing platform repo (hub ArgoCD applies it; tenants never write it —
decision D3), one ArgoCD `Application` + manifests per descriptor under
tenant-scoped paths:

```
tenants/<slug>/
├── project/                      # manifests descriptor: native AppProject tenant-<slug>
│   ├── application.yaml          #   (default project, argocd ns)
│   └── manifests/00-appproject-tenant-<slug>.yaml
├── dns/                          # manifests descriptor: native ExternalDNS DNSEndpoint
│   ├── application.yaml          #   (project tenant-<slug>, destination tenant-<slug>)
│   └── manifests/00-dnsendpoint-<slug>.yaml
├── namespace/                    # kro descriptor: TenantNamespace instance
│   ├── application.yaml          #   (default project; instance in ns "default" — the
│   └── instance.yaml             #    namespaced RGD creates tenant-<slug> itself)
└── keycloak/
    └── realm/                    # crossplane descriptor: TenantRealm claim
        ├── application.yaml      #   (project tenant-<slug>, destination tenant-<slug>)
        └── manifests/00-tenantrealm-<slug>.yaml
```

Key differences from the legacy render:

- **Native resources, no facade CRs.** cert-manager/ExternalDNS/ArgoCD
  objects (`DNSEndpoint`, `AppProject`) are committed directly; the
  `TenantNamespace` instance targets the KRO RGD (`stacks.inari.io/v1alpha1`,
  release-bundle `charts/inari-platform-graphs`); Keycloak realm/clients are
  Crossplane `provider-keycloak` claims (`identity.inari.io/v1alpha1`
  `TenantRealm`/`TenantClient`).
- **Render-time validation moved server-side.** DNS zone containment (every
  record must live inside the shared platform zone) is validated before
  commit; the dexidp chart repo (`https://charts.dexidp.io`) is auto-unioned
  into every tenant AppProject's `sourceRepos` (both ported from the
  operator's controllers).
- **AppProject as guardrail (D3).** Tenant-scoped Applications run under
  the per-tenant AppProject `tenant-<slug>`, which restricts destinations
  to the tenant namespace and sources to the platform repo + dex chart repo.
  `impersonateServiceAccount` is dropped — the write path is server → git →
  hub ArgoCD, authorized at the repo level.
- **Registration renders a claim.** `agentgateway.RegisterCluster` renders
  the per-cluster OIDC client as a `TenantClient` claim (plus the ESO
  `SecretStore`/`ExternalSecret` plumbing that materializes the credentials
  Secret in the tenant namespace) into
  `tenants/<slug>/keycloak/client-<id>/`, before the registration token is
  burned (failures keep the token consumable; retries re-commit identical
  content). During dual-run the `keycloak-client` desired-state row is
  upserted alongside the claim so the resources view is unchanged; the
  Admin API provisioning and ESO secret delivery for the agent bootstrap
  are likewise unchanged until the provider-keycloak cutover (Phase 3).
- **Status fold-back.** The agent's configurable GVR watches report the new
  kinds (`TenantRealm.identity.inari.io`,
  `TenantClient.identity.inari.io`, `DNSEndpoint.externaldns.k8s.io`,
  `TenantNamespace.stacks.inari.io`); the status sink maps them onto the
  same `platform_resources` rows the legacy CRs reported against.

Teardown (`tenantzonefactory.DeleteTenantManifests`) deletes the union of
legacy, descriptor, and per-cluster client-claim paths (the latter
enumerated from the tenant's `keycloak-client` rows), so tenants rendered
by either generation are removed cleanly.

**Cutover procedure.** The tenant-scoped Applications rendered at cluster
registration (TenantClient claims) run under the per-tenant AppProject
`tenant-<slug>`, which is only committed by the tenant render above. Flip
order therefore matters: enable the flag, then re-render every existing
tenant (the ops reconcile endpoint commits the descriptor set) before new
cluster registrations rely on the claim path — a registration in between
commits a claim Application whose AppProject does not exist yet (ArgoCD
sync error until the tenant render lands; self-healing, but noisy).

## Cluster Dex fan-out (operator sunset Phase 2, decision D5)

The ClusterDex CR/controller is replaced by a server-rendered ArgoCD
**ApplicationSet pair** per baseline repo (`internal/clusterdex`), fanned
out by a **list generator** over server-side inventory selectors — never
ArgoCD cluster-secret labels (engine-agnostic: Flux/Fleet possible later
without selector changes):

- `dex/applicationset.yaml` — official dexidp chart (pinned via
  `INARI_DEX_CHART_VERSION`, default 0.25.2) with the hardened baseline
  values ported 1:1 from the operator (default-deny egress except DNS/443,
  PDB, non-root/seccomp, resource limits), `configSecret.create=false`
  against the ESO-synced `dex-config` Secret, and per-cluster overlays at
  `clusters/<cluster>/dex/values.yaml` (`fullnameOverride: dex-<id>` pins
  the Service name so the deterministic issuer
  `http://dex-<id>.dex.svc.cluster.local:5556/dex` stays valid).
- `argocd-config/applicationset.yaml` — the `inari-platform` chart (OCI,
  pinned via `INARI_PLATFORM_CHART_VERSION`; empty disables this appset)
  with only its argocd section enabled, rendering the fail-closed
  `argocd-cm`/`argocd-rbac-cm` baseline and, when
  `INARI_ESO_SECRET_STORE` is set, the ExternalSecrets projecting the
  cluster's Dex material from Vault. Per-cluster overlays at
  `clusters/<cluster>/argocd-config/values.yaml` carry the issuer, the
  secret references, and the team-derived group mapping.

**Selector model:** every active/degraded org cluster gets the baseline;
the inventory label `inari.io/dex=disabled` opts a cluster out. Clusters
are grouped by their bound baseline repo (`clusters.baseline_repo_id`,
falling back to the org default); each repo's committed appset lists the
full matched membership (review/audit form), while the **delivery** is
per-cluster: the agent bridge upserts a single-element view of each appset
into that cluster's own ArgoCD (the appset controller is cluster-local, so
a multi-element appset would deploy siblings' Dex instances locally).
Delivery queue IDs are content-versioned, so changed manifests redeliver
despite the queue's idempotency-by-ID. Generated child Applications carry
the ArgoCD resources finalizer: removing a cluster's element (opt-out,
deletion) prunes its Dex.

**Triggers** (outbox consumer `clusterdex-reconcile`): `cluster.registered`
(registration, label changes — labels only mutate via re-registration —
and baseline rebinds), `cluster.deleted`, `team.created`/`team.deleted`,
`rbac.mappings.updated`, `tenant.created`, and `git.webhook.pr_merged`
(PR-policy repos: delivery waits for the merge). Re-render + commit happen
only on drift. The `cluster_dex.fanout` runtime flag is the kill-switch
(default on — there is no legacy render path to dual-run, D7).

**RBAC mapping** derives from the tenant's teams: admin-role teams map to
`role:admin`, all others to `role:readonly`; group paths are the Keycloak
full paths (`/tenant-<slug>/<team>`) — the same contract as
`rbacmaterialize`. `policy.default` stays empty (fail closed).

**Secret provisioning (unchanged seam):** registration
(`agentgateway.RegisterCluster`) provisions the `cluster-<id>-dex` Keycloak
client (`tenancy.CreateClusterDexClient`) and writes the Dex `config.yaml`
(Keycloak connector + `argocd` static client) and the static-client secret
to the cluster's Vault path (`inari/clusters/<id>/oidc-client-secret`, keys
`dex-config-yaml` / `dex-argocd-client-secret`). Secret values never touch
git, logs, or status; the rendered manifests reference the ESO-synced
Secrets by name/key only.
