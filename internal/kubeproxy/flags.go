// Package kubeproxy is the kubectl gateway data plane (plan §7.2): it
// terminates user kubectl TLS on /proxy/*, validates Keycloak JWTs
// statelessly, checks OpenFGA cluster:kubectl per request, mints
// Impersonate-* headers, and muxes HTTP requests onto per-cluster tunnel
// streams dialed out by in-cluster inari-tunnel-agents. It is stateless
// except in-memory tunnel sessions; audit and heartbeats go to the shared
// Postgres.
package kubeproxy

import "context"

// FlagEvaluator is the feature-flag seam (kill-switch v2). The standard
// implementation is featureflags.Resolver (OpenFeature client over the DB
// provider); StaticFlagEvaluator below serves tests and env-only wiring.
type FlagEvaluator interface {
	// KubectlAccessEnabled reports whether the kubectl_access.enabled flag
	// is on for the cluster ("" = platform scope). When off, the proxy
	// answers 410 and tunnel streams are rejected/closed.
	KubectlAccessEnabled(ctx context.Context, clusterID string) bool
}

// StaticFlagEvaluator is the env-only evaluator: one process-wide value
// (explicit INARI_KUBECTL_ACCESS_ENABLED override).
type StaticFlagEvaluator struct{ Enabled bool }

// KubectlAccessEnabled implements FlagEvaluator.
func (s StaticFlagEvaluator) KubectlAccessEnabled(context.Context, string) bool { return s.Enabled }
