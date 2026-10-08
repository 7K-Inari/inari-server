package featureflags

import (
	"context"

	"github.com/open-feature/go-sdk/openfeature"
)

// ExternalProviderDomain is the OpenFeature named-provider domain the
// optional external provider (OFREP, e.g. Flipt) registers under when
// INARI_FLAGS_PROVIDER is configured.
const ExternalProviderDomain = "inari-external"

// Resolver is the read path every consumer uses: explicitly SET env
// overrides win over runtime state, everything else evaluates through an
// OpenFeature client. Routing follows the ADR-0016 authority rule: flags
// registered AuthorityExternalAllowed resolve through the external client
// (when wired) at platform scope, everything else — kill-switches and all
// cluster-scoped evaluation — stays on the DB provider.
//
// Resolver satisfies both flag seams: kubeproxy.FlagEvaluator and
// clusterregistry.AccessFlagEvaluator.
type Resolver struct {
	client       *openfeature.Client
	extClient    *openfeature.Client
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

// WithExternal wires the external-provider client (nil = DB provider for all
// flags). Returns the resolver for chaining.
func (r *Resolver) WithExternal(ext *openfeature.Client) *Resolver {
	r.extClient = ext
	return r
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
	client := r.clientFor(def, clusterID)
	if client == nil {
		return def.Default
	}
	evalCtx := openfeature.NewEvaluationContext("", map[string]any{})
	if clusterID != "" {
		evalCtx = openfeature.NewEvaluationContext(clusterID, map[string]any{
			AttrScope:     string(ScopeCluster),
			AttrClusterID: clusterID,
		})
	}
	return client.Boolean(ctx, key, def.Default, evalCtx)
}

// clientFor routes evaluation per the authority rule: external-allowed flags
// use the external client at platform scope when one is wired; cluster-scoped
// evaluation and DB-authoritative flags always use the DB client.
func (r *Resolver) clientFor(def Definition, clusterID string) *openfeature.Client {
	if clusterID == "" && def.authority() == AuthorityExternalAllowed && r.extClient != nil {
		return r.extClient
	}
	return r.client
}

// KubectlAccessEnabled resolves the kubectl_access.enabled flag for a
// cluster ("" = platform scope). Implements kubeproxy.FlagEvaluator and
// clusterregistry.AccessFlagEvaluator.
func (r *Resolver) KubectlAccessEnabled(ctx context.Context, clusterID string) bool {
	return r.Bool(ctx, KeyKubectlAccessEnabled, clusterID)
}
