package renderer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func testParams() RenderParams {
	return RenderParams{
		Name: "cert-manager", Namespace: "cert-manager", ID: "abc123",
		AppPrefix: PrefixAddon, DeployMode: types.AddonDeployModeApplication,
		Clusters:   []ClusterTarget{{ID: "c1", Name: "prod-eu"}},
		RepoURL:    "https://github.com/acme/acme-inari-state",
		BaseBranch: "main", Path: "addons/cert-manager",
	}
}

func TestRegistryDispatchesAllKinds(t *testing.T) {
	r := New(nil)
	for _, kind := range []types.SourceKind{
		types.SourceKindHelm, types.SourceKindKRO, types.SourceKindCrossplane,
		types.SourceKindManifests, types.SourceKindKustomize,
	} {
		if _, ok := r.handlers[kind]; !ok {
			t.Errorf("no handler registered for kind %q", kind)
		}
	}
}

func TestRenderUnknownKind(t *testing.T) {
	r := New(nil)
	_, err := r.Render(context.Background(), types.SourceDescriptor{Kind: "bogus"}, testParams())
	if err == nil || !strings.Contains(err.Error(), `no handler registered for source kind "bogus"`) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderRequiresKindPayload(t *testing.T) {
	r := New(nil)
	_, err := r.Render(context.Background(), types.SourceDescriptor{Kind: types.SourceKindHelm}, testParams())
	if err == nil || !strings.Contains(err.Error(), `requires its helm payload`) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderValidatesParams(t *testing.T) {
	r := New(nil)
	desc := types.SourceDescriptor{Kind: types.SourceKindManifests, Manifests: &types.ManifestSource{}}

	p := testParams()
	p.ID = ""
	if _, err := r.Render(context.Background(), desc, p); err == nil {
		t.Fatal("expected error for empty ID")
	}

	p = testParams()
	p.Path = ""
	if _, err := r.Render(context.Background(), desc, p); err == nil {
		t.Fatal("expected error for empty Path")
	}

	p = testParams()
	p.Clusters = append(p.Clusters, ClusterTarget{ID: "c2", Name: "prod-us"})
	if _, err := r.Render(context.Background(), desc, p); err == nil ||
		!strings.Contains(err.Error(), "exactly one cluster") {
		t.Fatalf("application mode with 2 clusters: err = %v", err)
	}

	p = testParams()
	p.DeployMode = types.AddonDeployModeApplicationSet
	p.Clusters = nil
	if _, err := r.Render(context.Background(), desc, p); err == nil ||
		!strings.Contains(err.Error(), "at least one cluster") {
		t.Fatalf("applicationset mode without clusters: err = %v", err)
	}

	p = testParams()
	p.DeployMode = "fleet"
	if _, err := r.Render(context.Background(), desc, p); err == nil ||
		!strings.Contains(err.Error(), `unknown deploy mode "fleet"`) {
		t.Fatalf("err = %v", err)
	}
}

func TestStubHandlersReturnNotSupported(t *testing.T) {
	r := New(nil)
	p := testParams()
	for _, tc := range []struct {
		kind types.SourceKind
		desc types.SourceDescriptor
	}{
		{types.SourceKindCrossplane, types.SourceDescriptor{Kind: types.SourceKindCrossplane, Crossplane: &types.XPSource{}}},
		{types.SourceKindKustomize, types.SourceDescriptor{Kind: types.SourceKindKustomize, Kustomize: &types.KustomizeSource{Path: "base"}}},
	} {
		_, err := r.Render(context.Background(), tc.desc, p)
		if !errors.Is(err, ErrNotSupported) {
			t.Errorf("%s: err = %v, want ErrNotSupported", tc.kind, err)
		}
		if !strings.Contains(err.Error(), string(tc.kind)) {
			t.Errorf("%s: error should name the kind: %v", tc.kind, err)
		}
	}
}

func TestAppName(t *testing.T) {
	p := testParams()
	if got := p.appName(); got != "inari-addon-abc123" {
		t.Errorf("addon appName = %q", got)
	}
	p.AppPrefix = PrefixInstance
	if got := p.appName(); got != "inari-abc123" {
		t.Errorf("instance appName = %q", got)
	}
	p.DeployMode = types.AddonDeployModeApplicationSet
	if got := p.appName(); got != "inari-addonset-abc123" {
		t.Errorf("appset appName = %q", got)
	}
	p.DeployMode = types.AddonDeployModeApplication
	p.AppPrefix = ""
	if got := p.appName(); got != "abc123" {
		t.Errorf("verbatim appName = %q", got)
	}
}
