# inari-server — Agent Guide

Control plane for Inari: REST API/BFF, agent gRPC gateway, tenancy & identity, cluster registry, catalog service, orchestrator, cloud accounts, resources inventory, audit, approvals, notifications, extension host, fleet manager, policy service, tenant zone factory (plan §5.2).

Stack: Go, PostgreSQL, chi/Huma (REST/OpenAPI codegen), gRPC (agent gateway), NATS (event bus), OpenFGA (authz)

## Key architecture constraints
- **Modular monolith**: one deployable binary; every module (Tenancy, Cluster Registry, Agent Gateway, Catalog, Orchestrator, Cloud Accounts, Resources Inventory, Audit, Approvals, Notifications, Extension Host, Fleet Manager, Policy Service, Tenant Zone Factory) behind a strict internal interface so it can be extracted later (§5.2).
- Gateway = coarse PEP (valid JWT + org claim, route-level); services = fine PEP via OpenFGA `Check`/`ListObjects` behind an `Authorizer` interface (§5.4).
- Never store tenant kubeconfigs or cloud keys — only role ARNs, external IDs, OIDC metadata (§4.1, §5.10).
- Audit + events via the **outbox pattern** (append-only audit_events; outbox → NATS drives the OpenFGA tuple writer) (§5.2, §5.4).
- Tenancy = Keycloak **Organizations** in one `inari` realm; tenant ID is stable `org:<id>`; teams = groups `tenant-<slug>/<team>` (§5.4).
- Contracts (protobuf/OpenAPI) come from the `inari-api` repo — pin its versioned packages; never fork contract types (§6).

## Conventions
- Conventional Commits; SemVer releases; container images/artifacts cosign-signed (once CI exists).
- Write tests for new behavior; keep changes minimal and focused.
- Canonical architecture & development plan: https://github.com/7K-Inari/inari-docs/blob/main/docs/architecture/inari-platform-plan.md (section references below point into it).

## Platform design principles (apply everywhere)
1. Tenant-aware to the core — every object carries a tenant ID; every API decision is tenant-scoped.
2. Zero tenant credentials on the hub — no tenant kubeconfigs or cloud keys in the control plane.
3. Pull, never push — agents dial out; the control plane never initiates connections into tenant networks.
4. Desired state, eventually reconciled — GitOps/CR-based mutations, not imperative RPCs.
5. The catalog is a projection of reality — capabilities are discovered, not declared.
6. Small kernel, everything else extension.
7. Modular monolith first — strict internal module boundaries.
