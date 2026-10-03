// Package kubeproxy is the kubectl gateway data plane (plan §7.2): it
// terminates user kubectl TLS on /proxy/*, validates Keycloak JWTs
// statelessly, checks OpenFGA cluster:kubectl per request, mints
// Impersonate-* headers, and muxes HTTP requests onto per-cluster tunnel
// streams dialed out by in-cluster inari-tunnel-agents. It is stateless
// except in-memory tunnel sessions; audit and heartbeats go to the shared
// Postgres.
package kubeproxy

import "context"

// FlagEvaluator is the feature-flag seam (task f368d08b will deliver the
// env/file/provider-backed implementation). The static evaluator below is
// the interim default: kubectl_access.enabled defaults to true.
type FlagEvaluator interface {
	// KubectlAccessEnabled reports whether the kubectl_access.enabled flag
	// is on. When off, the proxy answers 410 and tunnel streams are
	// rejected/closed.
	KubectlAccessEnabled(ctx context.Context) bool
}

// StaticFlagEvaluator is the interim evaluator: one process-wide value from
// configuration (INARI_KUBECTL_ACCESS_ENABLED, default true).
type StaticFlagEvaluator struct{ Enabled bool }

// KubectlAccessEnabled implements FlagEvaluator.
func (s StaticFlagEvaluator) KubectlAccessEnabled(context.Context) bool { return s.Enabled }
