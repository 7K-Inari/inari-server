package scaffold

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"net/http/httptest"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/oci"
)

func setupTrustedTemplateRegistry(t *testing.T) *RegistryTemplateSource {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	pushTemplate(t, host, "templates/go-service", "1.0.0", TemplateMediaType, templateFiles())
	ref, err := name.ParseReference(host+"/templates/go-service:1.0.0", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := remote.Head(ref)
	if err != nil {
		t.Fatal(err)
	}
	digest := descriptor.Digest.String()
	index := fmt.Sprintf(`apiVersion: inari.dev/v1
kind: TemplateIndex
mediaType: application/vnd.inari.template.index.v1+yaml
sourceSha: abcdef0123456789abcdef0123456789abcdef01
sourceRef: refs/heads/main
producer:
  workflowPath: .github/workflows/release.yml
  workflowSha: 0123456789abcdef0123456789abcdef01234567
  runId: "123"
  runAttempt: 1
  runUri: https://github.com/7k-hiroba/argocd/actions/runs/123
templates:
  - name: go-service
    version: "1.0.0"
    packageVersion: "1.0.0"
    channel: stable
    type: template
    description: Minimal Go HTTP service
    ociRef: %s/templates/go-service:1.0.0
    digest: %s
    sourceSha: abcdef0123456789abcdef0123456789abcdef01
    releaseTag: go-service-v1.0.0
    mediaType: application/vnd.inari.template.v1
    producer:
      workflowPath: .github/workflows/release-oci.yml
      workflowSha: 0123456789abcdef0123456789abcdef01234567
      runId: "123"
      runAttempt: 1
      runUri: https://github.com/7k-hiroba/argocd/actions/runs/123
    lanes:
      - name: validate-template
        required: true
        status: passed
        runId: "123"
        jobId: "456"
        sourceSha: abcdef0123456789abcdef0123456789abcdef01
`, host, digest)
	pushTemplate(t, host, "templates/index", "latest", trustedsource.TemplateIndexMediaType, map[string]string{"templates.yaml": index})
	source := trustedsource.Source{
		IndexRef: host + "/templates/index:latest", TrustTier: trustedsource.TrustExperimental,
		AllowUnsigned: trustedsource.AllowUnsignedDevelopmentOnly, ArtifactPrefixes: []string{host + "/"},
	}
	return &RegistryTemplateSource{
		IndexRef: source.IndexRef, Source: source, CacheDir: t.TempDir(), Insecure: true,
		Verifier: artifactadmission.NewVerifier(artifactadmission.NewCosignBackend(&oci.Fetcher{Insecure: true})),
	}
}

func TestRegistryTemplateSourceSyncAndExactGet(t *testing.T) {
	source := setupTrustedTemplateRegistry(t)
	packages, err := source.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 || packages[0].Manifest.Name != "go-service" {
		t.Fatalf("packages = %+v", packages)
	}
	catalogPackages, err := (CatalogTemplatePuller{source}).Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalogPackages) != 1 || catalogPackages[0].Type != "template" || len(catalogPackages[0].ManifestJSON) == 0 || catalogPackages[0].SkeletonDigest == "" {
		t.Fatalf("catalog packages = %+v", catalogPackages)
	}
	entry := catalogPackages[0].Entry
	pkg, err := source.GetArtifact(context.Background(), entry.OCIRef+"@"+entry.Digest, "1.0.0", catalogPackages[0].SkeletonDigest)
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Manifest.Name != "go-service" || pkg.SkeletonDigest != catalogPackages[0].SkeletonDigest {
		t.Fatalf("exact package = %+v", pkg)
	}
}

func TestRegistryTemplateSourceDetectsCacheTamper(t *testing.T) {
	source := setupTrustedTemplateRegistry(t)
	catalogPackages, err := (CatalogTemplatePuller{source}).Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := source.Get(context.Background(), "go-service", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg.Dir, "skeleton", "deploy", "app.yaml"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := catalogPackages[0].Entry
	if _, err := source.GetArtifact(context.Background(), entry.OCIRef+"@"+entry.Digest, "1.0.0", catalogPackages[0].SkeletonDigest); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("error = %v, want skeleton digest mismatch", err)
	}
	if _, err := source.Get(context.Background(), "missing", "1.0.0"); err == nil {
		t.Fatal("missing template unexpectedly triggered an index refresh or succeeded")
	}
}
