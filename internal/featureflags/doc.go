// Package featureflags is Inari's standard runtime feature-flag mechanism
// (kill-switch v2; ADR-0014 addendum in inari-docs). It replaces per-binary
// static env flags as the default control: flag state is defined once in the
// feature_flags table (migration 0032) and read through the OpenFeature SDK.
//
// # Adding a flag
//
//  1. Register a Definition in registry.go (key, type, allowed scopes,
//     built-in default, description). The REST catalog endpoint serves it.
//  2. Read it via Resolver.Bool(ctx, key, clusterID) — never os.Getenv.
//  3. If the flag has an env kill-switch, parse it with
//     config.optionalBoolEnv and feed it into NewResolver's envOverrides at
//     startup: an explicitly SET env always wins over runtime state.
//
// # Backend authority rule
//
// Kill-switches and cluster-scoped flags are DB-authoritative even when an
// external OpenFeature provider (Unleash, flagd, ...) is configured for
// product/rollout flags: an external outage must not flip a kill switch, and
// per-cluster scoping + the audit trail live in Postgres. The data plane
// (inari-kubeproxy) reads the DB provider only — it never calls an external
// flag service at runtime.
//
// # Consistency
//
// Writes bump the shared generation key GenerationKey after commit
// (authz InvalidatingStore precedent); reads cache effective values stamped
// with the generation and a TTL (INARI_CACHE_FLAGS_TTL). Redis-backed
// deployments converge immediately; memory-backed ones within the TTL. All
// store/cache errors fail open to the flag's built-in default.
package featureflags
