package tenantzonefactory

import (
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func TestRenderBaselineAgentApplication(t *testing.T) {
	c := &types.Cluster{ID: "cl-1", OrgID: "org-1", Name: "acme-eks", Labels: map[string]string{"env": "zone", "region": "eu-west-1"}}
	zone := &types.TenantZone{Slug: "acme", Region: "eu-west-1"}
	p := AgentInstallParams{
		ImageRepo:      "ghcr.io/7k-inari/inari-agent",
		GatewayAddress: "https://gw.example",
	}
	files, err := RenderBaseline(c, zone, "tok-xyz", p, "https://git.example/acme-inari-state")
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = string(f.Content)
	}
	app, ok := byPath["baseline/inari-agent/application.yaml"]
	if !ok {
		t.Fatalf("missing application.yaml (has %v)", byPath)
	}
	for _, want := range []string{
		"kind: Application",
		"name: inari-agent",
		"namespace: argocd",
		"repoURL: ghcr.io/7k-inari/charts",
		"chart: inari-agent",
		`targetRevision: "*"`,
		"repository: ghcr.io/7k-inari/inari-agent",
		"tag: latest",
		"tenantID: org-1",
		"controlPlane: https://gw.example",
		"registrationToken: tok-xyz",
		"clusterLabels: env=zone,region=eu-west-1",
		"CreateNamespace=true",
	} {
		if !strings.Contains(app, want) {
			t.Errorf("application missing %q:\n%s", want, app)
		}
	}
	if strings.Contains(app, "oidcSecret") {
		t.Error("oidcSecret values must be omitted without ESO configuration")
	}
	if strings.Contains(app, "kubeconfig") {
		t.Error("application must never contain a kubeconfig")
	}
	// The old drift-prone rendered manifest must be gone.
	if _, ok := byPath["baseline/inari-agent/install.yaml"]; ok {
		t.Error("install.yaml must no longer be committed; the chart is the source of truth")
	}
}

func TestRenderBaselineAgentApplicationPinned(t *testing.T) {
	c := &types.Cluster{ID: "cl-1", OrgID: "org-1", Name: "acme-eks"}
	zone := &types.TenantZone{Slug: "acme", Region: "eu-west-1"}
	p := AgentInstallParams{
		ImageRepo:      "ghcr.io/7k-inari/inari-agent",
		GatewayAddress: "https://gw.example",
		Version:        "0.5.1",
	}
	files, err := RenderBaseline(c, zone, "tok-xyz", p, "https://git.example/acme-inari-state")
	if err != nil {
		t.Fatal(err)
	}
	var app string
	for _, f := range files {
		if f.Path == "baseline/inari-agent/application.yaml" {
			app = string(f.Content)
		}
	}
	for _, want := range []string{
		"targetRevision: 0.5.1",
		"tag: 0.5.1",
	} {
		if !strings.Contains(app, want) {
			t.Errorf("pinned application missing %q:\n%s", want, app)
		}
	}
	for _, unwanted := range []string{`targetRevision: "*"`, "tag: latest"} {
		if strings.Contains(app, unwanted) {
			t.Errorf("pinned application must not contain %q:\n%s", unwanted, app)
		}
	}
}

func TestRenderBaselineAgentApplicationFloatLatestEscapeHatch(t *testing.T) {
	c := &types.Cluster{ID: "cl-1", OrgID: "org-1", Name: "acme-eks"}
	zone := &types.TenantZone{Slug: "acme", Region: "eu-west-1"}
	p := AgentInstallParams{
		ImageRepo:      "ghcr.io/7k-inari/inari-agent",
		GatewayAddress: "https://gw.example",
		Version:        "0.5.1",
		FloatLatest:    true,
	}
	files, err := RenderBaseline(c, zone, "tok-xyz", p, "https://git.example/acme-inari-state")
	if err != nil {
		t.Fatal(err)
	}
	var app string
	for _, f := range files {
		if f.Path == "baseline/inari-agent/application.yaml" {
			app = string(f.Content)
		}
	}
	for _, want := range []string{`targetRevision: "*"`, "tag: latest"} {
		if !strings.Contains(app, want) {
			t.Errorf("FloatLatest application missing %q:\n%s", want, app)
		}
	}
}

func TestRenderBaselineAgentApplicationWithESO(t *testing.T) {
	c := &types.Cluster{ID: "cl-9", OrgID: "org-1", Name: "acme-eks"}
	zone := &types.TenantZone{Slug: "acme", Region: "eu-west-1"}
	p := AgentInstallParams{
		ImageRepo:      "ghcr.io/7k-inari/inari-agent",
		GatewayAddress: "https://gw.example",
		ESOSecretStore: "inari-platform",
	}
	files, err := RenderBaseline(c, zone, "tok", p, "https://git.example/acme-inari-state")
	if err != nil {
		t.Fatal(err)
	}
	var app string
	for _, f := range files {
		if f.Path == "baseline/inari-agent/application.yaml" {
			app = string(f.Content)
		}
	}
	for _, want := range []string{
		"oidcSecret:",
		"create: true",
		"name: inari-agent-oidc-client",
		"key: client-secret",
		"secretStore: inari-platform",
		"secretStoreKind: ClusterSecretStore",
		"remotePath: inari/clusters/cl-9/oidc-client-secret",
	} {
		if !strings.Contains(app, want) {
			t.Errorf("application missing %q:\n%s", want, app)
		}
	}
}

func TestRenderBaselineRequiresParams(t *testing.T) {
	c := &types.Cluster{ID: "c", OrgID: "org"}
	zone := &types.TenantZone{Slug: "acme"}
	if _, err := RenderBaseline(c, zone, "t", AgentInstallParams{}, "u"); err == nil {
		t.Error("want error for missing image repo")
	}
	if _, err := RenderBaseline(c, zone, "t", AgentInstallParams{ImageRepo: "img"}, "u"); err == nil {
		t.Error("want error for missing gateway address")
	}
}
