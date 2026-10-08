// Package featureflags is Inari's standard runtime feature-flag mechanism
// (kill-switch v2, ADR-0014 addendum). Flag state lives in the feature_flags
// table (migration 0032) and is read through the OpenFeature SDK: the DB
// provider here is the built-in default backend; external providers
// (Unleash, flagd, ...) plug in via the same OpenFeature seam later.
//
// Rules of the standard (see doc.go for the full guide):
//   - every runtime flag is registered in registry.go;
//   - kill-switches and cluster-scoped flags are DB-authoritative, even if an
//     external provider is configured for product/rollout flags;
//   - an explicitly SET env override always wins over runtime state.
package featureflags

// Scope is the level a flag value is written at.
type Scope string

const (
	// ScopePlatform is the platform-wide default (scope_key '').
	ScopePlatform Scope = "platform"
	// ScopeCluster is a per-cluster override (scope_key = cluster id).
	ScopeCluster Scope = "cluster"
)

// FlagType is the value shape of a flag. v1 supports booleans only.
type FlagType string

// FlagTypeBoolean is a true/false flag.
const FlagTypeBoolean FlagType = "boolean"

// Definition is the in-code registry entry for one flag.
type Definition struct {
	Key         string
	Type        FlagType
	Scopes      []Scope
	Default     bool
	Description string
}

// AllowsScope reports whether the flag may be written at scope.
func (d Definition) AllowsScope(scope Scope) bool {
	for _, s := range d.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// KeyKubectlAccessEnabled gates kubectl access through the gateway: off →
// 410 on proxy/kubeconfig and tunnel-stream rejection (kill-switch v2).
const KeyKubectlAccessEnabled = "kubectl_access.enabled"

// registry is the single source of truth for runtime flags. Add new flags
// here; the REST catalog endpoint serves this list.
var registry = []Definition{
	{
		Key:    KeyKubectlAccessEnabled,
		Type:   FlagTypeBoolean,
		Scopes: []Scope{ScopePlatform, ScopeCluster},
		// true preserves pre-flag behavior (INARI_KUBECTL_ACCESS_ENABLED
		// defaulted to true).
		Default:     true,
		Description: "kubectl access via inari-kubeproxy (410 proxy/kubeconfig + tunnel rejection when off)",
	},
}

// Catalog returns every registered flag definition.
func Catalog() []Definition {
	out := make([]Definition, len(registry))
	copy(out, registry)
	return out
}

// Lookup returns the definition for key.
func Lookup(key string) (Definition, bool) {
	for _, d := range registry {
		if d.Key == key {
			return d, true
		}
	}
	return Definition{}, false
}
