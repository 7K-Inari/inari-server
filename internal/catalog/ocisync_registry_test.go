package catalog

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/oci"
	inaritypes "github.com/7K-Inari/inari-server/internal/types"
)

const (
	registrySourceSHA   = "abcdef0123456789abcdef0123456789abcdef01"
	registryWorkflowSHA = "0123456789abcdef0123456789abcdef01234567"
)

type testArtifactImage struct {
	v1.Image
	artifactType string
}

func (i testArtifactImage) manifest() (*v1.Manifest, error) {
	manifest, err := i.Image.Manifest()
	if err != nil {
		return nil, err
	}
	copy := *manifest
	copy.ArtifactType = i.artifactType
	return &copy, nil
}

func (i testArtifactImage) Manifest() (*v1.Manifest, error) { return i.manifest() }

func (i testArtifactImage) RawManifest() ([]byte, error) {
	manifest, err := i.manifest()
	if err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

func pushArtifact(t *testing.T, registryHost, repo, tag, artifactType string, files map[string]string) string {
	t.Helper()
	var img v1.Image = empty.Image
	for file, content := range files {
		layer := static.NewLayer([]byte(content), types.MediaType("application/vnd.inari.catalog.package.v1+yaml"))
		var err error
		img, err = mutate.Append(img, mutate.Addendum{Layer: layer, Annotations: map[string]string{"org.opencontainers.image.title": file}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if artifactType != "" {
		img = testArtifactImage{Image: img, artifactType: artifactType}
	}
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", registryHost, repo, tag), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	descriptor, err := remote.Head(ref)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.Digest.String()
}

func testChartYAML(host, digest string) string {
	return fmt.Sprintf(`repoURL: oci://%s/charts
chart: external-secrets
namespace: external-secrets
channels:
  stable:
    version: "0.10.5"
    ociRef: %s/charts/external-secrets:0.10.5
    digest: %s
  incubating:
    version: "0.10.5"
    ociRef: %s/charts/external-secrets:0.10.5
    digest: %s
`, host, host, digest, host, digest)
}

func helmChartBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	content := []byte("apiVersion: v2\nname: external-secrets\nversion: 0.10.5\n")
	if err := writer.WriteHeader(&tar.Header{Name: "external-secrets/Chart.yaml", Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pushHelmChart(t *testing.T, host string) string {
	t.Helper()
	var img v1.Image = empty.Image
	layer := static.NewLayer(helmChartBytes(t), types.MediaType(trustedsource.HelmChartMediaType))
	img, err := mutate.Append(img, mutate.Addendum{Layer: layer})
	if err != nil {
		t.Fatal(err)
	}
	img = mutate.ConfigMediaType(img, types.MediaType("application/vnd.cncf.helm.config.v1+json"))
	ref, err := name.ParseReference(host+"/charts/external-secrets:0.10.5", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	descriptor, err := remote.Head(ref)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.Digest.String()
}

const testPackageYAML = `version: 1.0.0
channel: stable
type: platform-app
description: External Secrets Operator
`

func indexEntryYAML(name, version, packageVersion, channel, typ, description, ref, digest, chartRef, chartDigest string) string {
	chartMetadata := ""
	if typ == "platform-app" {
		chartMetadata = fmt.Sprintf(`    chartRef: oci://%s
    chartDigest: %s
    chartProducer:
      workflowPath: .github/workflows/release-chart.yml
      workflowSha: 0123456789abcdef0123456789abcdef01234567
      runId: "124"
      runAttempt: 1
      runUri: https://github.com/7k-hiroba/argocd/actions/runs/124
`, chartRef, chartDigest)
	}
	return fmt.Sprintf(`  - name: %s
    version: %q
    packageVersion: %q
    channel: %q
    type: %q
    description: %q
    ociRef: %q
    digest: %q
    sourceSha: %q
    releaseTag: %q
    mediaType: application/vnd.inari.catalog.package.v1+yaml
%s    producer:
      workflowPath: .github/workflows/release-oci.yml
      workflowSha: %q
      runId: "123"
      runAttempt: 1
      runUri: https://github.com/7k-hiroba/argocd/actions/runs/123
    lanes:
      - name: test-packages
        required: true
        status: passed
        runId: "123"
        jobId: "456"
        sourceSha: %q
`, name, version, packageVersion, channel, typ, description, ref, digest, registrySourceSHA, name+"-v"+packageVersion, chartMetadata, registryWorkflowSHA, registrySourceSHA)
}

func testIndexYAML(host string, entries ...string) string {
	return fmt.Sprintf(`apiVersion: inari.dev/v1
kind: CatalogIndex
mediaType: application/vnd.inari.catalog.index.v1+yaml
sourceSha: %q
sourceRef: refs/heads/main
producer:
  workflowPath: .github/workflows/release.yml
  workflowSha: %q
  runId: "123"
  runAttempt: 1
  runUri: https://github.com/7k-hiroba/argocd/actions/runs/123
packages:
%s`, registrySourceSHA, registryWorkflowSHA, strings.Join(entries, ""))
}

func setupFakeCatalog(t *testing.T) *RegistryPuller {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	chartDigest := pushHelmChart(t, host)
	externalDigest := pushArtifact(t, host, "catalog/external-secrets", "1.0.0", "application/vnd.inari.catalog.package.v1+yaml", map[string]string{
		"package.yaml": testPackageYAML, "chart.yaml": testChartYAML(host, chartDigest),
		"values.schema.json": `{"type":"object","properties":{"installCRDs":{"type":"boolean"}}}`,
	})
	webDigest := pushArtifact(t, host, "catalog/web-service", "0.1.0", "application/vnd.inari.catalog.package.v1+yaml", map[string]string{
		"package.yaml":  "version: 0.1.0\nchannel: incubating\ntype: kro-rgd\n",
		"rgd.yaml":      "apiVersion: kro.run/v1alpha1\nkind: ResourceGraphDefinition\n",
		"schema.json":   `{"type":"object"}`,
		"ui-hints.yaml": "fields:\n  - name: image\n    widget: text\n",
	})
	entries := indexEntryYAML("external-secrets", "0.10.5", "1.0.0", "stable", "platform-app", "External Secrets Operator", host+"/catalog/external-secrets:1.0.0", externalDigest, host+"/charts/external-secrets:0.10.5", chartDigest) +
		indexEntryYAML("web-service", "0.1.0", "0.1.0", "incubating", "kro-rgd", "Web service golden path", host+"/catalog/web-service:0.1.0", webDigest, "", "")
	pushArtifact(t, host, "catalog/index", "latest", "application/vnd.inari.catalog.index.v1+yaml", map[string]string{"catalog.yaml": testIndexYAML(host, entries)})
	source := trustedSourceForRegistry(host)
	return &RegistryPuller{
		IndexRef: host + "/catalog/index:latest", Source: source, Insecure: true,
		Verifier: artifactadmission.NewVerifier(artifactadmission.NewCosignBackend(&oci.Fetcher{Insecure: true})),
	}
}

func trustedSourceForRegistry(host string) trustedsource.Source {
	return trustedsource.Source{
		IndexRef: host + "/catalog/index:latest", TrustTier: trustedsource.TrustExperimental,
		AllowUnsigned:    trustedsource.AllowUnsignedDevelopmentOnly,
		ArtifactPrefixes: []string{host + "/"},
	}
}

func TestRegistryPuller(t *testing.T) {
	p := setupFakeCatalog(t)
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var external, web []Package
	for _, pkg := range pkgs {
		switch pkg.Name {
		case "external-secrets":
			external = append(external, pkg)
		case "web-service":
			web = append(web, pkg)
		}
	}
	if len(external) != 2 || len(web) != 1 {
		t.Fatalf("packages = %d external / %d web", len(external), len(web))
	}
	channels := []string{external[0].Channel, external[1].Channel}
	sort.Strings(channels)
	if channels[0] != "incubating" || channels[1] != "stable" {
		t.Errorf("channels = %v", channels)
	}
	for _, pkg := range external {
		if pkg.Version != "0.10.5" || pkg.Chart == nil || pkg.Chart.Digest == "" || pkg.Entry.PackageVersion != "1.0.0" {
			t.Errorf("external-secrets[%s] = %+v", pkg.Channel, pkg)
		}
		if !strings.Contains(string(pkg.Schema), "installCRDs") {
			t.Errorf("schema = %s", pkg.Schema)
		}
		if !strings.Contains(pkg.OCIRef, "@sha256:") {
			t.Errorf("mutable package ref = %q", pkg.OCIRef)
		}
	}
	if web[0].Version != "0.1.0" || web[0].Channel != "incubating" || len(web[0].RGD) == 0 || len(web[0].Schema) == 0 {
		t.Errorf("web-service = %+v", web[0])
	}
	if !strings.Contains(string(web[0].UIHints), "fields") {
		t.Errorf("UI hints = %s", web[0].UIHints)
	}
}

func TestSyncPlanCanonicalIdentityAndChannels(t *testing.T) {
	p := setupFakeCatalog(t)
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	items, versions, err := syncPlan("core", pkgs)
	if err != nil {
		t.Fatal(err)
	}
	versionsByItem := map[string][]inaritypes.CatalogItemVersion{}
	for i, version := range versions {
		versionsByItem[version.ItemID] = append(versionsByItem[version.ItemID], *version)
		if items[i].ID != version.ItemID || items[i].SourceID != "core" || !items[i].SnapshotPresent || !version.SnapshotPresent {
			t.Errorf("non-canonical mapping: %+v / %+v", items[i], version)
		}
	}
	for _, channel := range []string{"stable", "incubating"} {
		got, err := resolveChannelVersion("", versionsByItem["core/external-secrets"], "core/external-secrets", channel)
		if err != nil || got != "0.10.5" {
			t.Errorf("channel %s resolved %q, %v", channel, got, err)
		}
	}
	got, err := resolveChannelVersion("", versionsByItem["core/web-service"], "core/web-service", "incubating")
	if err != nil || got != "0.1.0" {
		t.Errorf("web-service resolved %q, %v", got, err)
	}
}

func TestRegistryRejectsMissingSignature(t *testing.T) {
	p := setupFakeCatalog(t)
	p.Source.TrustTier = trustedsource.TrustOfficial
	p.Source.AllowUnsigned = ""
	p.Source.Publisher = trustedsource.Publisher{
		Issuer: "https://token.actions.githubusercontent.com", Repository: "example/fixture",
		Workflows: trustedsource.DefaultArtifactWorkflows(), WorkflowSHA: registryWorkflowSHA,
		SourceRepository: "example/fixture", SourceWorkflow: ".github/workflows/release.yml",
	}
	if _, err := p.Pull(context.Background()); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("signed source unexpectedly accepted without signature: %v", err)
	}
}

func TestEffectiveVersionErrorMessage(t *testing.T) {
	_, err := resolveChannelVersion("", nil, "core/external-secrets", "stable")
	if err == nil || !strings.Contains(err.Error(), `core/external-secrets`) {
		t.Fatalf("error = %v", err)
	}
}
