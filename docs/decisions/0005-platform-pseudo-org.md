# ADR 0005: Platform pseudo-org for the platform cluster

## Status
Accepted (M7.W2)

## Context
Design decision D1: the 7kgroup platform cluster registers with the control
plane like any other cluster (cluster registry record, one-time registration
token, per-cluster OIDC client, agent event stream). The cluster registry and
agent gateway are org-scoped, so the platform cluster needs an owning org.
The catalog module already scopes platform audit rows to `OrgID "platform"`,
but no Keycloak Organization / `organizations` row backs that slug.

`tenancy.CreateTenant` cannot create it: it is user-coupled (creator
auto-membership in the Keycloak org + `platform-team` group + membership
tuple outbox) and is gated behind the interactive `POST /api/v1/tenants`
flow. Seeding needs an internal, actor-free, idempotent path.

## Decision
A reserved **`platform` Keycloak org** (`tenancy.PlatformOrgSlug`) is created
at control-plane startup by `tenancy.Service.SeedPlatformOrg`:

- Creates the Keycloak Organization (`alias=platform`), the `organizations`
  row (`org:<kcOrgID>`), and the standard default teams
  (`platform-team`/`developers`/`viewers`) so ADR-0004 group→tuple sync and
  route-level FGA checks work for ops users who join the org.
- Emits the standard `tenant.created` outbox event so OpenFGA base tuples
  are seeded by the existing tuple writer.
- Records audit rows with actor `system:seed`; **no creator membership** is
  written (there is no human actor).
- Idempotent: an existing `platform` org is a no-op; a concurrent seed
  losing the unique-slug race is treated as success. Mirrors the
  `catalog.SeedPlatformApps` startup-seed pattern.

The platform cluster then follows the unmodified tenant flow: org member
mints a registration token → renders the install manifest → agent dials out
(`pull, never push`). `agentgateway.AuthorizeCluster` and
`clusterregistry/manifest.go` are org-agnostic and required **no changes**.
The server-rendered manifest grants no `platform.inari.io` CRD access; the
agent-side RBAC for that lives in the inari-agent repo and must use a
ClusterRole name distinct from `inari-agent-discovery` to avoid conflicting
with the server-rendered RBAC.

## Alternatives considered
- **CLI subcommand** (`inari-server seed-platform-org`): explicit, but adds
  command plumbing and an ops step that can be forgotten; deviates from the
  `SeedPlatformApps` precedent.
- **SQL migration for the `organizations` row + manual Keycloak org**:
  breaks the Keycloak-as-source-of-truth invariant, requires a hardcoded
  `keycloak_org_id`, and skips the FGA tuple-seeding outbox event.

## Consequences
- Every environment (dev and prod) gets the platform org at startup; a
  Keycloak outage surfaces as a startup error, same as the catalog seed.
- Ops users must be added to the Keycloak `platform` org (and
  `tenant-platform/platform-team` group) before they can register the
  platform cluster through the REST API — see `docs/platform-cluster.md`.
- The reserved slug `platform` can never be taken by a customer tenant.
