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

// FlagAuthority declares which backend is authoritative for a flag
// (ADR-0016 authority rule).
type FlagAuthority string

const (
	// AuthorityDB marks a flag DB-authoritative: kill-switches and every
	// cluster-scoped flag always resolve through the DB provider, even when
	// an external provider is configured — an external outage must never
	// flip them.
	AuthorityDB FlagAuthority = "db"
	// AuthorityExternalAllowed marks a platform-scoped product/rollout flag
	// that MAY be served by the external provider (OFREP, e.g. Flipt) when
	// INARI_FLAGS_PROVIDER is configured; the DB provider serves it
	// otherwise. Cluster-scoped evaluation always stays on the DB provider.
	AuthorityExternalAllowed FlagAuthority = "external-allowed"
)

// Definition is the in-code registry entry for one flag.
type Definition struct {
	Key         string
	Type        FlagType
	Scopes      []Scope
	Default     bool
	Description string
	// Authority defaults to AuthorityDB when empty.
	Authority FlagAuthority
}

// authority normalizes the zero value to AuthorityDB.
func (d Definition) authority() FlagAuthority {
	if d.Authority == "" {
		return AuthorityDB
	}
	return d.Authority
}

// validateRegistry panics on an inconsistent registry entry (authority rule:
// cluster-scoped flags are always DB-authoritative). Called by tests and by
// Lookup's callers implicitly relying on a sane registry.
func validateRegistry() {
	for _, d := range registry {
		if d.AllowsScope(ScopeCluster) && d.authority() != AuthorityDB {
			panic("featureflags: flag " + d.Key + " allows cluster scope but is not DB-authoritative")
		}
	}
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
		// Kill-switch: DB-authoritative even with an external provider.
		Authority: AuthorityDB,
	},
}

func init() { validateRegistry() }

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
