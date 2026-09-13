package catalog

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	inaritypes "github.com/7K-Inari/inari-server/internal/types"
)

// pushArtifact pushes an oras-style artifact (one layer per file, file name
// in the title annotation) to the fake registry.
func pushArtifact(t *testing.T, registryHost, repo, tag string, files map[string]string) {
	t.Helper()
	img := empty.Image
	for file, content := range files {
		layer := static.NewLayer([]byte(content), types.MediaType("application/vnd.inari.catalog.package.v1+yaml"))
		var err error
		img, err = mutate.Append(img, mutate.Addendum{
			Layer: layer,
			Annotations: map[string]string{
				"org.opencontainers.image.title": file,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryHost, repo, tag), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
}

const testChartYAML = `repoURL: https://charts.external-secrets.io
chart: external-secrets
namespace: external-secrets
channels:
  stable: "0.10.5"
  incubating: "0.10.5"
`

const testPackageYAML = `version: 1.0.0
channel: stable
type: platform-app
description: External Secrets Operator
`

const testIndexYAML = `apiVersion: inari.dev/v1alpha1
kind: CatalogIndex
packages:
  - name: external-secrets
    version: "1.0.0"
    channel: "stable"
    type: "platform-app"
    description: "External Secrets Operator"
    ociRef: "%[1]s/catalog/external-secrets:1.0.0"
    channelRef: "%[1]s/catalog/external-secrets:stable"
  - name: web-service
    version: "0.1.0"
    channel: "incubating"
    type: "kro-rgd"
    description: "Web service golden path"
    ociRef: "%[1]s/catalog/web-service:0.1.0"
    channelRef: "%[1]s/catalog/web-service:incubating"
`

func setupFakeCatalog(t *testing.T) *RegistryPuller {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	u, _ := url.Parse(srv.URL)
	_ = u

	pushArtifact(t, host, "catalog/external-secrets", "stable", map[string]string{
		"package.yaml": testPackageYAML,
		"chart.yaml":   testChartYAML,
	})
	pushArtifact(t, host, "catalog/web-service", "incubating", map[string]string{
		"package.yaml": "version: 0.1.0\nchannel: incubating\ntype: kro-rgd\n",
		"rgd.yaml":     "apiVersion: kro.run/v1alpha1\nkind: ResourceGraphDefinition\n",
		"schema.json":  `{"type":"object"}`,
	})
	pushArtifact(t, host, "catalog/index", "latest", map[string]string{
		"catalog.yaml": fmt.Sprintf(testIndexYAML, host),
	})
	return &RegistryPuller{IndexRef: host + "/catalog/index:latest", Insecure: true}
}

func TestRegistryPuller(t *testing.T) {
	p := setupFakeCatalog(t)
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// external-secrets expands to one package per chart channel.
	var es, ws []Package
	for _, pkg := range pkgs {
		switch pkg.Name {
		case "external-secrets":
			es = append(es, pkg)
		case "web-service":
			ws = append(ws, pkg)
		}
	}
	if len(es) != 2 {
		t.Fatalf("external-secrets packages = %d, want 2 (one per channel)", len(es))
	}
	channels := []string{es[0].Channel, es[1].Channel}
	sort.Strings(channels)
	if channels[0] != "incubating" || channels[1] != "stable" {
		t.Errorf("external-secrets channels = %v", channels)
	}
	for _, pkg := range es {
		if pkg.Version != "0.10.5" {
			t.Errorf("external-secrets[%s].Version = %q, want 0.10.5 (chart version)", pkg.Channel, pkg.Version)
		}
		if pkg.Chart == nil || pkg.Chart.RepoURL != "https://charts.external-secrets.io" {
			t.Errorf("external-secrets[%s].Chart = %+v", pkg.Channel, pkg.Chart)
		}
		if pkg.Type != "platform-app" {
			t.Errorf("external-secrets[%s].Type = %q", pkg.Channel, pkg.Type)
		}
	}
	if len(ws) != 1 {
		t.Fatalf("web-service packages = %d, want 1", len(ws))
	}
	if ws[0].Version != "0.1.0" || ws[0].Channel != "incubating" {
		t.Errorf("web-service = %s@%s", ws[0].Channel, ws[0].Version)
	}
	if len(ws[0].RGD) == 0 {
		t.Error("web-service RGD empty")
	}
	if len(ws[0].Schema) == 0 {
		t.Error("web-service schema empty")
	}
}

func TestSyncPlanPlatformAppMapping(t *testing.T) {
	p := setupFakeCatalog(t)
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	items, versions, err := syncPlan(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != len(versions) {
		t.Fatalf("items %d != versions %d", len(items), len(versions))
	}
	versionsByItem := map[string][]inaritypes.CatalogItemVersion{}
	for i, v := range versions {
		versionsByItem[v.ItemID] = append(versionsByItem[v.ItemID], *v)
		if items[i].ID != v.ItemID {
			t.Errorf("item %s mismatched with version for %s", items[i].ID, v.ItemID)
		}
	}
	// Platform apps reconcile onto the seeded platform:<name> items so
	// EffectiveVersion("platform:external-secrets", "stable") resolves.
	for _, ch := range []string{"stable", "incubating"} {
		got, err := resolveChannelVersion("", versionsByItem["platform:external-secrets"], "platform:external-secrets", ch)
		if err != nil {
			t.Fatalf("platform:external-secrets channel %q: %v", ch, err)
		}
		if got != "0.10.5" {
			t.Errorf("platform:external-secrets[%s] = %q, want 0.10.5", ch, got)
		}
	}
	// Non-platform packages keep the curated: prefix and their RGD payload.
	got, err := resolveChannelVersion("", versionsByItem["curated:web-service"], "curated:web-service", "incubating")
	if err != nil {
		t.Fatalf("curated:web-service: %v", err)
	}
	if got != "0.1.0" {
		t.Errorf("curated:web-service = %q, want 0.1.0", got)
	}
	for _, it := range items {
		if it.ID == "platform:external-secrets" && it.Source != inaritypes.CatalogSourcePlatform {
			t.Errorf("platform:external-secrets source = %q, want platform", it.Source)
		}
		if it.ID == "curated:web-service" && it.Source != inaritypes.CatalogSourceCurated {
			t.Errorf("curated:web-service source = %q, want curated", it.Source)
		}
	}
}

// TestEffectiveVersionErrorMessage is the deploy-path regression test for
// the reported failure: with no synced versions the exact error is
// produced; after a sync plan the same lookup resolves.
func TestEffectiveVersionErrorMessage(t *testing.T) {
	_, err := resolveChannelVersion("", nil, "platform:external-secrets", "stable")
	if err == nil {
		t.Fatal("expected error with no versions")
	}
	want := `catalog: no version of platform:external-secrets in channel "stable"`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}

	p := setupFakeCatalog(t)
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, versions, err := syncPlan(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	var esVersions []inaritypes.CatalogItemVersion
	for _, v := range versions {
		if v.ItemID == "platform:external-secrets" {
			esVersions = append(esVersions, *v)
		}
	}
	got, err := resolveChannelVersion("", esVersions, "platform:external-secrets", "stable")
	if err != nil {
		t.Fatalf("after sync: %v", err)
	}
	if got != "0.10.5" {
		t.Errorf("resolved = %q, want 0.10.5", got)
	}
}

// TestAllPlatformAppsResolveAfterSync proves every seeded platform app gets
// a resolvable stable version from a registry sync.
func TestAllPlatformAppsResolveAfterSync(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	charts := map[string]struct{ repoURL, chart, namespace, version string }{
		"keycloak":         {"https://charts.bitnami.com/bitnami", "keycloak", "keycloak", "24.4.2"},
		"cert-manager":     {"https://charts.jetstack.io", "cert-manager", "cert-manager", "1.16.2"},
		"external-secrets": {"https://charts.external-secrets.io", "external-secrets", "external-secrets", "0.10.5"},
		"argocd":           {"https://argoproj.github.io/argo-helm", "argo-cd", "argocd", "7.7.3"},
	}
	var indexEntries strings.Builder
	for name, c := range charts {
		pushArtifact(t, host, "catalog/"+name, "stable", map[string]string{
			"package.yaml": "version: 1.0.0\nchannel: stable\ntype: platform-app\n",
			"chart.yaml": fmt.Sprintf("repoURL: %s\nchart: %s\nnamespace: %s\nchannels:\n  stable: %q\n",
				c.repoURL, c.chart, c.namespace, c.version),
		})
		fmt.Fprintf(&indexEntries, `  - name: %s
    version: "1.0.0"
    channel: "stable"
    type: "platform-app"
    ociRef: "%[2]s/catalog/%[1]s:1.0.0"
    channelRef: "%[2]s/catalog/%[1]s:stable"
`, name, host)
	}
	pushArtifact(t, host, "catalog/index", "latest", map[string]string{
		"catalog.yaml": "apiVersion: inari.dev/v1alpha1\nkind: CatalogIndex\npackages:\n" + indexEntries.String(),
	})

	p := &RegistryPuller{IndexRef: host + "/catalog/index:latest", Insecure: true}
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, versions, err := syncPlan(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	versionsByItem := map[string][]inaritypes.CatalogItemVersion{}
	for _, v := range versions {
		versionsByItem[v.ItemID] = append(versionsByItem[v.ItemID], *v)
	}
	want := map[string]string{
		"platform:keycloak":         "24.4.2",
		"platform:cert-manager":     "1.16.2",
		"platform:external-secrets": "0.10.5",
		"platform:argocd":           "7.7.3",
	}
	for _, seeded := range PlatformApps {
		resolved, err := resolveChannelVersion("", versionsByItem[seeded.ID], seeded.ID, "stable")
		if err != nil {
			t.Errorf("%s: %v", seeded.ID, err)
			continue
		}
		if resolved != want[seeded.ID] {
			t.Errorf("%s resolved %q, want %q", seeded.ID, resolved, want[seeded.ID])
		}
	}
}
