package featureflags

import (
	"context"

	"github.com/open-feature/go-sdk/openfeature"
)

// Resolver is the read path every consumer uses: explicitly SET env
// overrides win over runtime state, everything else evaluates through the
// OpenFeature client (DB provider by default; external providers plug into
// the same client later — kill-switches stay DB-authoritative regardless).
//
// Resolver satisfies both flag seams: kubeproxy.FlagEvaluator and
// clusterregistry.AccessFlagEvaluator.
type Resolver struct {
	client       *openfeature.Client
	envOverrides map[string]bool
}

// NewResolver builds the resolver. envOverrides maps flag keys to their
// explicitly-set env values (config optionalBoolEnv); nil/empty = runtime
// flags fully in control.
func NewResolver(client *openfeature.Client, envOverrides map[string]bool) *Resolver {
	if envOverrides == nil {
		envOverrides = map[string]bool{}
	}
	return &Resolver{client: client, envOverrides: envOverrides}
}

// EnvOverride reports whether key is pinned by an explicitly set env
// override, and to what value. API responses surface this so operators can
// see why a runtime write is inert.
func (r *Resolver) EnvOverride(key string) (value, pinned bool) {
	v, ok := r.envOverrides[key]
	return v, ok
}

// Bool resolves a boolean flag. clusterID non-empty requests cluster-scoped
// evaluation (cluster override → platform default → built-in default).
func (r *Resolver) Bool(ctx context.Context, key, clusterID string) bool {
	if v, ok := r.envOverrides[key]; ok {
		return v
	}
	def, ok := Lookup(key)
	if !ok || def.Type != FlagTypeBoolean {
		return false
	}
	if r.client == nil {
		return def.Default
	}
	evalCtx := openfeature.NewEvaluationContext("", map[string]any{})
	if clusterID != "" {
		evalCtx = openfeature.NewEvaluationContext(clusterID, map[string]any{
			AttrScope:     string(ScopeCluster),
			AttrClusterID: clusterID,
		})
	}
	return r.client.Boolean(ctx, key, def.Default, evalCtx)
}

// KubectlAccessEnabled resolves the kubectl_access.enabled flag for a
// cluster ("" = platform scope). Implements kubeproxy.FlagEvaluator and
// clusterregistry.AccessFlagEvaluator.
func (r *Resolver) KubectlAccessEnabled(ctx context.Context, clusterID string) bool {
	return r.Bool(ctx, KeyKubectlAccessEnabled, clusterID)
}
