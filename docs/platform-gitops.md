# Platform GitOps: per-tenant platform resources

M7.W2. Every tenant gets three base platform resources tracked in the control
plane (`platform_resources` table, status `reconciling` until the platform
reconciler reports back) and rendered as inari-operator `api/v1alpha1` CRs in
the platform GitOps repo:

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
  (retry-safe).
- `tenantzonefactory` "wire into Inari" step (`ModuleWiring.WireZone`) —
  re-ensures the base rows (idempotent; safe on zone step retries) and, when
  `INARI_PLATFORM_GITOPS_REPO` is set, renders the CR manifests
  (`platformresources.RenderTenantManifests`) and commits them to the platform
  GitOps repo through the `gitprovider.Provider` seam.
- Startup backfill (`cmd/inari-server/main.go`) — after migrations, ensures
  base rows for all pre-existing tenants (best-effort, logged, idempotent).

Out of scope here: the reconciler status sink (separate task) and resource
deletion on tenant/zone teardown.
