# Platform cluster registration (7kgroup)

Ops procedure for registering the 7kgroup platform cluster under the reserved
`platform` pseudo-org (ADR-0005, design decision D1).

## 1. Seed the platform org

Automatic: `tenancy.Service.SeedPlatformOrg` runs at control-plane startup
and idempotently creates the Keycloak Organization `platform`, the
`organizations` row, and the default teams (`platform-team`, `developers`,
`viewers`). Audit rows are recorded with actor `system:seed`; no creator
membership exists.

Verify:

```sh
curl -H "Authorization: Bearer $TOKEN" \
  https://<control-plane>/api/v1/tenants/platform
```

## 2. Join the platform org

The cluster-registry REST routes require the caller to be a member of the
org (Keycloak org claim) and to hold a sufficient org role. Add the ops
user to:

- the Keycloak Organization `platform` (drives the org token claim), and
- the group `tenant-platform/platform-team` (grants platform-engineer via
  the ADR-0004 group→tuple sync; converges within one sync interval).

## 3. Register the cluster and render the install manifest

```sh
# Create the cluster record
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "7kgroup-platform"}' \
  https://<control-plane>/api/v1/tenants/platform/clusters

# Render the agent install manifest (embeds a fresh one-time registration
# token; plaintext is returned once, only its hash is stored)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://<control-plane>/api/v1/tenants/platform/clusters/<cluster-id>/install-manifest \
  > platform-agent.yaml
```

If `INARI_ENROLLMENT_APPROVAL_REQUIRED` is on, approve the cluster first
(`POST .../clusters/<cluster-id>/approve`).

## 4. Deploy the agent on the 7kgroup cluster

```sh
kubectl apply -f platform-agent.yaml
```

The agent dials out to the control plane (pull, never push), exchanges the
bootstrap token for its per-cluster OIDC identity, and connects the event
stream. Verify:

```sh
curl -H "Authorization: Bearer $TOKEN" \
  https://<control-plane>/api/v1/tenants/platform/clusters
# expect state=active and a recent lastSeenAt
```

## RBAC note (platform.inari.io CRDs)

The server-rendered manifest (`internal/clusterregistry/manifest.go`) grants
only generic discovery access (CRDs, nodes, Crossplane/kro/OLM watchers) via
the `inari-agent-discovery` ClusterRole — it deliberately contains **no**
`platform.inari.io` rules. Read access to the platform CRDs is added by the
inari-agent repo under a **separate ClusterRole name** so the two RBAC
sources never conflict; do not reuse `inari-agent-discovery` agent-side.
