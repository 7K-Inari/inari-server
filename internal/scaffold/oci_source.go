// The OCI-backed template source (M8.W6, parent plan §9 Slice 2): pulls
// application/vnd.inari.template.v1 artifacts from an OCI registry behind
// the TemplateSource seam, with optional cosign signature verification
// (same trust model as the server images) and a content-addressed local
// extraction cache so the run engine keeps its filesystem rendering path.
package scaffold

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/oci"
)

// TemplateMediaType is the OCI artifact type of a software-template
// package. Artifacts that declare a different type are rejected.
const TemplateMediaType = "application/vnd.inari.template.v1"

// SignatureVerifier verifies a template artifact's signature before it is
// ingested (cosign keyless, like the server images). NoopVerifier serves
// dev/tests and the pre-signing rollout.
type SignatureVerifier interface {
	Verify(ctx context.Context, ref string) error
}

// NoopVerifier accepts every reference.
type NoopVerifier struct{}

// Verify implements SignatureVerifier.
func (NoopVerifier) Verify(context.Context, string) error { return nil }

// templateIndex mirrors the template index artifact (an oras-pushed
// templates.yaml), the same index→artifacts pattern as the catalog sync.
type templateIndex struct {
	Templates []struct {
		Name        string `yaml:"name"`
		Version     string `yaml:"version"`
		Channel     string `yaml:"channel"`
		Description string `yaml:"description"`
		OCIRef      string `yaml:"ociRef"`
		ChannelRef  string `yaml:"channelRef"`
	} `yaml:"templates"`
}

// OCIRegistryPuller pulls software-template packages from an OCI registry:
// first the index artifact (e.g. ghcr.io/7k-inari/templates/index:latest),
// then each template artifact listed in it. Pulled packages are extracted
// under CacheDir keyed by content digest (immutable → extraction happens
// once) and memoized for the run engine's Get calls.
type OCIRegistryPuller struct {
	// IndexRef is the OCI reference of the template index artifact.
	IndexRef string
	// CacheDir receives the extracted template packages.
	CacheDir string
	// Keychain overrides registry auth (default: authn.DefaultKeychain).
	Keychain authn.Keychain
	// Insecure allows plain-HTTP registries (tests/dev).
	Insecure bool
	// Verifier gates ingestion on the artifact signature; nil means no
	// verification (equivalent to NoopVerifier).
	Verifier SignatureVerifier

	mu   sync.Mutex
	byID map[string]*TemplatePackage // "name@version"
}

func (p *OCIRegistryPuller) fetcher() *oci.Fetcher {
	return &oci.Fetcher{Keychain: p.Keychain, Insecure: p.Insecure}
}

// Pull fetches the index and every template artifact it lists. Like
// FilePuller it fails fast: one invalid (or unverifiable) artifact fails
// the whole pull.
func (p *OCIRegistryPuller) Pull(ctx context.Context) ([]TemplatePackage, error) {
	indexRaw, err := p.fetchFile(ctx, p.IndexRef, "templates.yaml")
	if err != nil {
		return nil, fmt.Errorf("scaffold: pull template index %s: %w", p.IndexRef, err)
	}
	var idx templateIndex
	if err := yaml.Unmarshal(indexRaw, &idx); err != nil {
		return nil, fmt.Errorf("scaffold: parse template index %s: %w", p.IndexRef, err)
	}
	var out []TemplatePackage
	for _, entry := range idx.Templates {
		ref := entry.ChannelRef
		if ref == "" {
			ref = entry.OCIRef
		}
		if ref == "" {
			return nil, fmt.Errorf("scaffold: index template %q has no ociRef", entry.Name)
		}
		pkg, err := p.pullOne(ctx, entry.Name, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, *pkg)
	}
	return out, nil
}

// pullOne verifies, fetches, guards and extracts one template artifact.
func (p *OCIRegistryPuller) pullOne(ctx context.Context, name, ref string) (*TemplatePackage, error) {
	if p.Verifier != nil {
		if err := p.Verifier.Verify(ctx, ref); err != nil {
			return nil, fmt.Errorf("scaffold: verify template %s (%s): %w", name, ref, err)
		}
	}
	art, err := p.fetcher().Fetch(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("scaffold: pull template %s (%s): %w", name, ref, err)
	}
	if art.MediaType != "" && art.MediaType != TemplateMediaType {
		return nil, fmt.Errorf("scaffold: template %s (%s): artifact type %q, want %q",
			name, ref, art.MediaType, TemplateMediaType)
	}
	if name == "" || name != filepath.Base(name) {
		return nil, fmt.Errorf("scaffold: invalid template name %q", name)
	}
	dir, err := p.extract(name, art)
	if err != nil {
		return nil, err
	}
	// Reuse the file source's parsing + validation (name↔manifest
	// invariant, required files, JSON well-formedness, skeleton digest).
	pkg, err := readTemplateDir(dir, name)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.byID == nil {
		p.byID = map[string]*TemplatePackage{}
	}
	p.byID[name+"@"+pkg.Manifest.Version] = pkg
	p.mu.Unlock()
	return pkg, nil
}

// extract writes the artifact's layers under
// <CacheDir>/<name>/<digest>/ (template.yaml, schema.json, uiSchema.json,
// skeleton/...). Content-addressed: an already-extracted digest is reused
// untouched.
func (p *OCIRegistryPuller) extract(name string, art *oci.Artifact) (string, error) {
	if p.CacheDir == "" {
		return "", errors.New("scaffold: OCI template source needs a cache dir (INARI_SCAFFOLD_TEMPLATE_CACHE_DIR)")
	}
	digest := strings.NewReplacer(":", "-", "/", "-").Replace(art.Digest)
	dir := filepath.Join(p.CacheDir, name, digest)
	marker := filepath.Join(dir, ".extracted")
	if _, err := os.Stat(marker); err == nil {
		return dir, nil
	}
	for rel, raw := range art.Files {
		clean := filepath.Clean(rel)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("scaffold: template layer name %q escapes the package dir", rel)
		}
		dst := filepath.Join(dir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(marker, []byte(art.Digest), 0o644); err != nil {
		return "", err
	}
	return dir, nil
}

// fetchFile pulls an oras-style artifact and returns the layer titled
// filename.
func (p *OCIRegistryPuller) fetchFile(ctx context.Context, ref, filename string) ([]byte, error) {
	files, err := p.fetcher().FetchDir(ctx, ref)
	if err != nil {
		return nil, err
	}
	raw, ok := files[filename]
	if !ok {
		return nil, fmt.Errorf("scaffold: %s: no layer named %q", ref, filename)
	}
	return raw, nil
}

// Get resolves one template package at an exact version, from the memoized
// packages when possible and falling back to a full Pull (a template added
// after startup, or a restart with a warm cache).
func (p *OCIRegistryPuller) Get(ctx context.Context, name, version string) (*TemplatePackage, error) {
	if name == "" || name != filepath.Base(name) {
		return nil, fmt.Errorf("scaffold: invalid template name %q", name)
	}
	key := name + "@" + version
	p.mu.Lock()
	pkg := p.byID[key]
	p.mu.Unlock()
	if pkg != nil {
		return pkg, nil
	}
	if _, err := p.Pull(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if pkg := p.byID[key]; pkg != nil {
		return pkg, nil
	}
	return nil, fmt.Errorf("scaffold: template %s version %s not found in the OCI template source", name, version)
}
