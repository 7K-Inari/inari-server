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
