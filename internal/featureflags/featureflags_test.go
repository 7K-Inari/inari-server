package featureflags

import (
	"context"
	"testing"

	"github.com/open-feature/go-sdk/openfeature"
)

func TestRegistryLookup(t *testing.T) {
	def, ok := Lookup(KeyKubectlAccessEnabled)
	if !ok {
		t.Fatal("kubectl_access.enabled not registered")
	}
	if def.Type != FlagTypeBoolean || !def.Default {
		t.Errorf("kubectl_access.enabled definition = %+v, want boolean default true", def)
	}
	if !def.AllowsScope(ScopePlatform) || !def.AllowsScope(ScopeCluster) {
		t.Errorf("kubectl_access.enabled scopes = %v, want platform+cluster", def.Scopes)
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("unknown key resolved")
	}
	for _, d := range Catalog() {
		if d.Key == "" || d.Description == "" || len(d.Scopes) == 0 {
			t.Errorf("incomplete registry entry: %+v", d)
		}
	}
}

func TestResolverEnvOverrideWins(t *testing.T) {
	// No OpenFeature provider registered: the client falls back to the
	// built-in default; env override must still win both ways.
	r := NewResolver(openfeature.NewClient("test-no-provider"), map[string]bool{KeyKubectlAccessEnabled: false})
	if r.KubectlAccessEnabled(context.Background(), "clu-1") {
		t.Error("env override false must win over the built-in default true")
	}
	r = NewResolver(openfeature.NewClient("test-no-provider"), map[string]bool{KeyKubectlAccessEnabled: true})
	if !r.KubectlAccessEnabled(context.Background(), "clu-1") {
		t.Error("env override true must win")
	}
	if v, pinned := r.EnvOverride(KeyKubectlAccessEnabled); !pinned || !v {
		t.Error("EnvOverride must report the pinned value")
	}
}

func TestResolverDefaultsWithoutOverride(t *testing.T) {
	r := NewResolver(openfeature.NewClient("test-no-provider-2"), nil)
	if !r.KubectlAccessEnabled(context.Background(), "") {
		t.Error("no rows + no env: built-in default true must apply")
	}
	if _, pinned := r.EnvOverride(KeyKubectlAccessEnabled); pinned {
		t.Error("no env set: must not report pinned")
	}
	// Nil client (export-openapi zero Deps): built-in default.
	r = NewResolver(nil, nil)
	if !r.Bool(context.Background(), KeyKubectlAccessEnabled, "clu-1") {
		t.Error("nil client must resolve to the built-in default")
	}
	if r.Bool(context.Background(), "unregistered.flag", "") {
		t.Error("unknown flag must resolve false")
	}
}
