# ADR 0015: Generic plan limits and metering seams

## Status

Accepted (BIL-1)

## Context

Generic enforcement points need a consistent way to resolve tenant cluster,
developer-seat and feature-gate limits without coupling the control plane to an
external plan authority. Usage producers also need a narrow event-emission seam
without downstream processing semantics. Enforcement and metering consumption
are separate follow-up work.

## Decision

`internal/planlimits` owns `PlanLimitsProvider` and `MeteringEventEmitter`.
The OSS defaults are `UnlimitedProvider` and `NoopMeteringEmitter`; numeric
limits are nil (unlimited), all features are enabled, and no metering event is
emitted unless explicitly configured.

The optional Keycloak provider reads the versioned
`inari.plan.limits.v1` Organization attribute. Its document is the public
`inari.planlimits.v1.PlanLimits` protobuf JSON representation. Absent numeric
fields mean unlimited, while present zero means zero allowed. Missing or
malformed attributes are errors in this opt-in provider, never silently
unlimited. `all_features` controls current and future gates; otherwise a gate
requires an explicit true entry.

The optional outbox emitter writes generic `metering.recorded` events through
the existing transactional outbox. Event IDs travel in the payload so consumers
can deduplicate at-least-once delivery. The control plane remains the replay
source of truth, and the events carry only generic measurements.

`INARI_PLAN_LIMITS_PROVIDER=unlimited|keycloak` defaults to `unlimited` and
`INARI_METERING_EMITTER=noop|outbox` defaults to `noop`. Main wires shared
instances into the tenancy and cluster-registry seams. BIL-3 owns actual
checks, denial behavior, hot-path caching, and invalidation.

## Consequences

- OSS behavior is unchanged and has no commercial runtime dependency.
- Limit documents are generic, versioned, and recoverable through Keycloak
  reconciliation rather than a lookup RPC on the future enforcement hot path.
- A missing attribute in the explicitly selected Keycloak mode is visible as a
  configuration/data error instead of accidentally granting unlimited limits.
- Direct provider reads are intentional in BIL-1; introducing per-request
  enforcement without BIL-3's cache policy would be premature.
