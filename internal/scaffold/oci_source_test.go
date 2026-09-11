package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// typedImage overrides the manifest artifact type (oras artifacts declare
// application/vnd.inari.template.v1; plain pushes leave it empty).
type typedImage struct {
	v1.Image
	mt string
}

func (t typedImage) manifest() (*v1.Manifest, error) {
	m, err := t.Image.Manifest()
	if err != nil {
		return nil, err
	}
	cp := *m
	cp.ArtifactType = t.mt
	return &cp, nil
}

func (t typedImage) Manifest() (*v1.Manifest, error) { return t.manifest() }

func (t typedImage) RawManifest() ([]byte, error) {
	m, err := t.manifest()
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// pushTemplate pushes a template package artifact (one layer per file).
func pushTemplate(t *testing.T, host, repo, tag, mediaType string, files map[string]string) {
	t.Helper()
	img := v1.Image(empty.Image)
	for file, content := range files {
		layer := static.NewLayer([]byte(content), types.MediaType("application/vnd.inari.template.layer.v1"))
		var err error
		img, err = mutate.Append(img, mutate.Addendum{
			Layer:       layer,
			Annotations: map[string]string{"org.opencontainers.image.title": file},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if mediaType != "" {
		img = typedImage{Image: img, mt: mediaType}
	}
	ref, err := name.ParseReference(fmt.Sprintf("%s/%s:%s", host, repo, tag), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
}

const testTemplateYAML = `name: go-service
displayName: Go Service
description: Minimal Go HTTP service
tags: [go, service]
version: 1.0.0
channel: stable
`

func templateFiles() map[string]string {
	return map[string]string{
		"template.yaml":            testTemplateYAML,
		"schema.json":              `{"type":"object"}`,
		"skeleton/deploy/app.yaml": "kind: Deployment\n",
		"skeleton/.github/ci.yaml": "name: ci\n",
	}
}

func pushTemplateIndex(t *testing.T, host string, entries string) {
	t.Helper()
	pushTemplate(t, host, "templates/index", "latest", "", map[string]string{
		"templates.yaml": "templates:\n" + entries,
	})
}

func setupFakeTemplateRegistry(t *testing.T) (string, *OCIRegistryPuller) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	pushTemplate(t, host, "templates/go-service", "stable", TemplateMediaType, templateFiles())
	pushTemplateIndex(t, host, fmt.Sprintf(`  - name: go-service
    version: "1.0.0"
    channel: "stable"
    ociRef: "%[1]s/templates/go-service:1.0.0"
    channelRef: "%[1]s/templates/go-service:stable"
`, host))
	return host, &OCIRegistryPuller{
		IndexRef: host + "/templates/index:latest",
		CacheDir: t.TempDir(),
		Insecure: true,
	}
}

func TestOCIRegistryPullerPull(t *testing.T) {
	host, p := setupFakeTemplateRegistry(t)
	pkgs, err := p.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %d, want 1", len(pkgs))
	}
	pkg := pkgs[0]
	if pkg.Manifest.Name != "go-service" || pkg.Manifest.Version != "1.0.0" || pkg.Manifest.Channel != "stable" {
		t.Errorf("manifest = %+v", pkg.Manifest)
	}
	if string(pkg.Schema) != `{"type":"object"}` {
		t.Errorf("schema = %s", pkg.Schema)
	}
	// Extraction: the skeleton tree landed in the content-addressed cache.
	if _, err := os.Stat(filepath.Join(pkg.Dir, "skeleton", "deploy", "app.yaml")); err != nil {
		t.Errorf("skeleton not extracted: %v", err)
	}
	if !strings.HasPrefix(pkg.Dir, p.CacheDir) {
		t.Errorf("package dir %q outside cache %q", pkg.Dir, p.CacheDir)
	}
	// Get resolves the memoized package at its exact version.
	got, err := p.Get(context.Background(), "go-service", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Dir != pkg.Dir {
		t.Errorf("Get dir = %q, want %q", got.Dir, pkg.Dir)
	}
	// A second pull reuses the extraction (marker file intact).
	if _, err := p.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(pkg.Dir, ".extracted")); err != nil {
		t.Errorf("extraction marker missing: %v", err)
	}
	_ = host
}

func TestOCIRegistryPullerGetUnknown(t *testing.T) {
	_, p := setupFakeTemplateRegistry(t)
	if _, err := p.Get(context.Background(), "go-service", "9.9.9"); err == nil {
		t.Fatal("expected error for unknown version")
	}
	if _, err := p.Get(context.Background(), "../escape", "1.0.0"); err == nil {
		t.Fatal("expected error for unsafe name")
	}
}

// recordingVerifier is a fake SignatureVerifier capturing the refs it saw.
type recordingVerifier struct {
	mu   sync.Mutex
	refs []string
	err  error
}

func (v *recordingVerifier) Verify(_ context.Context, ref string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refs = append(v.refs, ref)
	return v.err
}

func TestOCIRegistryPullerVerifier(t *testing.T) {
	_, p := setupFakeTemplateRegistry(t)
	v := &recordingVerifier{}
	p.Verifier = v
	if _, err := p.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(v.refs) != 1 || !strings.Contains(v.refs[0], "templates/go-service") {
		t.Fatalf("verified refs = %v", v.refs)
	}

	_, p2 := setupFakeTemplateRegistry(t)
	p2.Verifier = &recordingVerifier{err: errors.New("bad signature")}
	if _, err := p2.Pull(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "bad signature") {
		t.Fatalf("pull with failing verifier = %v, want bad signature error", err)
	}
}

func TestOCIRegistryPullerMediaTypeGuard(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	pushTemplate(t, host, "templates/go-service", "stable", "application/vnd.other.v1", templateFiles())
	pushTemplateIndex(t, host, fmt.Sprintf(`  - name: go-service
    version: "1.0.0"
    ociRef: "%[1]s/templates/go-service:stable"
`, host))
	p := &OCIRegistryPuller{IndexRef: host + "/templates/index:latest", CacheDir: t.TempDir(), Insecure: true}
	_, err := p.Pull(context.Background())
	if err == nil || !strings.Contains(err.Error(), TemplateMediaType) {
		t.Fatalf("wrong artifact type: err = %v, want media-type guard", err)
	}
}
