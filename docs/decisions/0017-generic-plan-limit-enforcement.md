# ADR 0017: Generic plan-limit enforcement

## Status

Accepted (BIL-3)

## Context

ADR 0015 introduced generic plan-limit lookup and an unlimited OSS default, but
left enforcement, cache behavior, and denial semantics to BIL-3. Enforcement
must cover both REST mutations and internal producers (outbox consumers,
resume handlers, and periodic sweeps). Route-only middleware would miss those
internal paths, and a commercial lookup RPC would put a proprietary dependency
on the public hot path.

## Decision

`internal/planlimits` owns a shared `Evaluator` and immutable per-operation
`Evaluation`. Modules resolve the generic document once, then perform pure
quota and feature checks. A nil evaluator and the default `UnlimitedProvider`
both mean nil numeric limits and all features enabled. Commercial plan names,
prices, and entitlement rules remain outside this repository.

The selected provider is wrapped in a per-tenant TTL cache with singleflight
miss coalescing. `INARI_PLAN_LIMITS_CACHE_TTL` defaults to 30 seconds; zero
disables caching. Only successful reads are cached. Expired data is never
served after a provider failure, and missing/malformed documents in explicit
Keycloak mode fail closed. Cache expiry is the invalidation mechanism because
BIL-1 writes the Keycloak attribute out of band.

Numeric denials return HTTP 429; feature denials return HTTP 403. Both use a
Huma-compatible `LimitExceededError` with `code=plan_limit_exceeded`, a generic
`limitKind`/`limit`, and usage/limit fields for quotas. Provider failures return
503 with `code=plan_limits_unavailable`, never an upgrade prompt. The optional
`INARI_PLAN_LIMITS_UPGRADE_URL` is a generic absolute HTTPS URL.

Cluster count and insert execute in one transaction under a per-tenant
PostgreSQL advisory transaction lock. Non-terminal states consume capacity;
decommissioned/revoked/deleted records do not. Developer-seat admission uses a
per-tenant session advisory lock around inline Keycloak and projection work,
counts distinct Organization members, and admits existing members without
charging another seat. Existing over-limit usage remains readable/removable
after a downgrade but cannot grow.

Feature gates are enforced at the service operation that produces new paid
work, including notification delivery/retry, policy distribution, rollout
advancement, and drift reporting. Disabled background production is skipped
without aborting other tenants. Reads and non-destructive cleanup remain
available. Auto-approved actions and platform safety lifecycle approvals are
not treated as paid approval usage.

`zone-vending` gates every vend/resume path and platform-context cloud account
registration; tenant-context BYO accounts remain available. Decommission is
not gated. Before a valid zone is wired, the owner's evaluated generic limits
are projected to the new child Organization with a replay-safe, full-
representation-preserving Keycloak update. No public code infers a commercial
tier from this gate.

## Consequences

- OSS self-host behavior remains unchanged and has no commercial dependency.
- Concurrent cluster registrations and inline invites cannot exceed a cap
  through a simple read-then-write race.
- Hosted plan changes become effective within the cache TTL, and transient
  provider failures do not silently grant entitlements.
- External IdP memberships are counted on subsequent admission checks, but a
  downgrade does not destructively unlink users or lock existing tenants out.
- Reconciliation can repair the versioned Keycloak document without adding a
  commercial RPC to request processing.
