package featureflags

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/open-feature/go-sdk/openfeature"
)

// recordingProvider returns a fixed value and counts evaluations.
type recordingProvider struct {
	value atomic.Bool
	calls atomic.Int64
}

func (p *recordingProvider) Metadata() openfeature.Metadata {
	return openfeature.Metadata{Name: "recording"}
}
func (p *recordingProvider) Hooks() []openfeature.Hook { return nil }
func (p *recordingProvider) BooleanEvaluation(_ context.Context, _ string, defaultValue bool, _ openfeature.FlattenedContext) openfeature.BoolResolutionDetail {
	p.calls.Add(1)
	v := p.value.Load()
	return openfeature.BoolResolutionDetail{
		Value: v,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason:  openfeature.StaticReason,
			Variant: variant(v),
		},
	}
}
func (p *recordingProvider) StringEvaluation(_ context.Context, _ string, d string, _ openfeature.FlattenedContext) openfeature.StringResolutionDetail {
	return openfeature.StringResolutionDetail{Value: d}
}
func (p *recordingProvider) FloatEvaluation(_ context.Context, _ string, d float64, _ openfeature.FlattenedContext) openfeature.FloatResolutionDetail {
	return openfeature.FloatResolutionDetail{Value: d}
}
func (p *recordingProvider) IntEvaluation(_ context.Context, _ string, d int64, _ openfeature.FlattenedContext) openfeature.IntResolutionDetail {
	return openfeature.IntResolutionDetail{Value: d}
}
func (p *recordingProvider) ObjectEvaluation(_ context.Context, _ string, d any, _ openfeature.FlattenedContext) openfeature.InterfaceResolutionDetail {
	return openfeature.InterfaceResolutionDetail{Value: d}
}

// withExternalAllowedFlag registers an external-allowed test flag for the
// duration of the test.
func withExternalAllowedFlag(t *testing.T, key string) {
	t.Helper()
	registry = append(registry, Definition{
		Key: key, Type: FlagTypeBoolean, Scopes: []Scope{ScopePlatform},
		Default: true, Description: "test flag", Authority: AuthorityExternalAllowed,
	})
	t.Cleanup(func() { registry = registry[:len(registry)-1] })
}

func TestRegistryAuthorityInvariant(t *testing.T) {
	// Every cluster-scoped flag must be DB-authoritative (ADR-0016 rule,
	// enforced by validateRegistry at package init).
	for _, d := range Catalog() {
		if d.AllowsScope(ScopeCluster) && d.authority() != AuthorityDB {
			t.Errorf("cluster-scoped flag %s is not DB-authoritative", d.Key)
		}
	}
	def, ok := Lookup(KeyKubectlAccessEnabled)
	if !ok || def.authority() != AuthorityDB {
		t.Error("kubectl_access.enabled must be DB-authoritative (kill-switch)")
	}
}

func TestResolverExternalRouting(t *testing.T) {
	const extKey = "test.external.allowed"
	withExternalAllowedFlag(t, extKey)

	dbProv := &recordingProvider{}
	dbProv.value.Store(true)
	extProv := &recordingProvider{}
	extProv.value.Store(false) // external says OFF; DB says ON — routing decides

	if err := openfeature.SetNamedProviderAndWait("test-ext-db", dbProv); err != nil {
		t.Fatal(err)
	}
	if err := openfeature.SetNamedProviderAndWait("test-ext-ext", extProv); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(openfeature.NewClient("test-ext-db"), nil).
		WithExternal(openfeature.NewClient("test-ext-ext"))
	ctx := context.Background()

	// External-allowed flag, platform scope, external wired → external wins.
	if r.Bool(ctx, extKey, "") {
		t.Error("external-allowed platform flag must resolve via the external provider")
	}
	// Cluster-scoped evaluation always stays on the DB provider (the
	// external service knows nothing about our cluster ids).
	if !r.Bool(ctx, extKey, "clu-1") {
		t.Error("cluster-scoped evaluation must stay on the DB provider")
	}
	// DB-authoritative flag (kubectl kill-switch) never touches the external
	// provider, even at platform scope.
	extCallsBefore := extProv.calls.Load()
	if !r.KubectlAccessEnabled(ctx, "") {
		t.Error("DB provider says on; resolver must not consult the external provider")
	}
	if got := extProv.calls.Load() - extCallsBefore; got != 0 {
		t.Errorf("DB-authoritative flag hit the external provider %d times", got)
	}
}

func TestResolverExternalFallbackWithoutExternal(t *testing.T) {
	const extKey = "test.external.fallback"
	withExternalAllowedFlag(t, extKey)

	dbProv := &recordingProvider{}
	dbProv.value.Store(false)
	if err := openfeature.SetNamedProviderAndWait("test-ext-solo", dbProv); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(openfeature.NewClient("test-ext-solo"), nil)
	if r.Bool(context.Background(), extKey, "") {
		t.Error("no external wired: external-allowed flag must resolve via the DB provider")
	}
}
