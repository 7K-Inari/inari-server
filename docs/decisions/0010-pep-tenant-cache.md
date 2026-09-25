# ADR 0010: PEP and tenant-resolution cache with optional Redis backend

## Status
Accepted

## Context
Every org-scoped request pays one Postgres slug→org lookup plus one OpenFGA
Check, duplicated across ~13 module handlers via the `authorizeOrg` pattern
(`internal/tenancy/http.go`). The worst endpoint,
`GET /api/v1/me/permissions`, costs 1 platform Check plus, per org in the
token, 1 DB lookup and up to 4 sequential role-ladder Checks — and the
console calls it on every load. The M1 spike
(`inari-docs/docs/spikes/m1-openfga-performance.md`) mandates a PEP cache
(1-5s TTL, keyed (user, relation, object), invalidated via tuple-writer
events) and measured ~4x p99 improvement from FGA-side caching. This is part
of the 99.9% availability initiative.

FGA tuple writes happen in four places, not just the outbox consumer:
`authz.TupleWriter`, `authz.PlatformGroupSync`, `authz.OrgTeamSync`, and
`tenancy.Deleter.stepFGACleanup`. Any invalidation scheme hooked only into
the outbox consumer would miss the reconcilers and the teardown.

## Decision
- **`internal/cache`**: a small `Cache` interface (Get/Set/Delete/Increment/
  Close, string values, TTL on Set) with two backends selected by
  `INARI_CACHE_BACKEND`: `memory` (default, in-process, bounded by
  `INARI_CACHE_MEMORY_MAX_ENTRIES`) and `redis` (`INARI_REDIS_URL`,
  go-redis/v9). The Redis client uses short dial/read/write timeouts because
  callers fail open.
- **PEP cache**: `authz.CachedAuthorizer` decorates the shared
  `authz.Authorizer`. Check results — allows *and* denies — are cached with
  `INARI_CACHE_PEP_TTL` (default 2s, spike range 1-5s) under keys
  `inari:fga:pep:<generation>:<user>|<relation>|<object>`.
- **Invalidation by generation bump**: `authz.InvalidatingStore` decorates
  the `authz.Store` handed to all four write paths; every successful
  Write/DeleteTuples increments `inari:fga:pep:gen`. New checks read under
  the new generation; old-generation entries expire via TTL (no DEL scans,
  no per-key tracking, no reimplementation of the FGA model's computed
  usersets). One decorator covers every writer because they all take a
  `Store`.
- **ListObjects is NOT cached**: its callers are reconcilers, not the
  per-request PEP hot path; a stale membership set is more dangerous than a
  stale single check; the spike flags it as the slowest but least frequent
  operation. The generation-stamped key scheme makes it safe to add later.
- **Tenant cache**: `tenancy.OrgCache` backs `Service.GetTenant` (the single
  funnel every module's authorizeOrg calls) with JSON-encoded org rows,
  `INARI_CACHE_TENANT_TTL` (default 10s). Only positive results are cached
  (org creation is immediately visible). Mutations invalidate: create
  (defensive), display-name update, status freeze/restore, and org-row
  deletion (the Deleter holds the same cache).
- **Fail-open everywhere**: any cache error degrades to a direct OpenFGA /
  Postgres call, logged (sampled: first, then every 100th) and metered.
  Requests never fail because the cache is down; TTL bounds staleness while
  generation bumps are lost. A Redis *startup* failure is fatal (the
  operator opted into the backend), runtime failures are not.
- **Metrics** (greenfield — the repo had none): OTel MeterProvider with a
  Prometheus exporter at `/metrics` (plain chi route, outside huma, so the
  published OpenAPI surface is unchanged). Series:
  `inari_cache_operations_total{cache,backend,op,result}` (hit ratio),
  `inari_fga_check_duration_seconds` + `inari_fga_check_total{cached}` (the
  p99 evidence), `inari_cache_invalidations_total`.
- **Chart**: optional bitnami/redis subchart (`redis.enabled=false`
  default; standalone, auth-less for e2e). `cache.backend=redis` renders
  `INARI_CACHE_BACKEND`/`INARI_REDIS_URL` (subchart service or `redis.url`
  BYO) and fails template rendering when neither is available.

## Consequences
- Single replica (or redis backend): invalidation is near-instant after a
  tuple write lands.
- Memory backend, multi-replica: generation bumps are process-local, so a
  grant/revocation may take up to `INARI_CACHE_PEP_TTL` to reach other
  replicas — same bound as the TTL-only design, acceptable per the spike.
- Benchmarks with simulated 5ms FGA latency
  (`internal/authz/cachepep_bench_test.go`): Check 5.3ms → 0.27ms,
  /me/permissions-style loop 32.5ms → 1.7ms per iteration.
- The agent-gateway command-queue polling rework is explicitly out of scope
  (separate follow-up).
