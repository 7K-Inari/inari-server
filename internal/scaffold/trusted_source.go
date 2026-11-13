package scaffold

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/oci"
	"github.com/google/go-containerregistry/pkg/authn"
)

// RegistryTemplateSource syncs strict template indexes and also resolves
// exact artifact digests for scaffold rendering. It never follows a mutable
// channel ref on a render-time cache miss.
type RegistryTemplateSource struct {
	IndexRef string
	Source   trustedsource.Source
	Verifier *artifactadmission.Verifier
	CacheDir string
	Keychain authn.Keychain
	Insecure bool

	mu   sync.Mutex
	byID map[string]*TemplatePackage
}

func (p *RegistryTemplateSource) fetcher() *oci.Fetcher {
	return &oci.Fetcher{Keychain: p.Keychain, Insecure: p.Insecure}
}

type CatalogTemplatePuller struct{ *RegistryTemplateSource }

func (p CatalogTemplatePuller) Pull(ctx context.Context) ([]catalog.Package, error) {
	return p.pullCatalog(ctx)
}

func (p *RegistryTemplateSource) pullCatalog(ctx context.Context) ([]catalog.Package, error) {
	if p.Verifier == nil {
		return nil, errors.New("scaffold: trusted source verifier is required")
	}
	indexArtifact, err := p.fetcher().Fetch(ctx, p.IndexRef)
	if err != nil {
		return nil, fmt.Errorf("scaffold: pull template index %s: %w", p.IndexRef, err)
	}
	raw, ok := indexArtifact.Files["templates.yaml"]
	if !ok {
		return nil, fmt.Errorf("scaffold: index %s has no templates.yaml layer", p.IndexRef)
	}
	idx, err := trustedsource.DecodeIndex(raw)
	if err != nil {
		return nil, fmt.Errorf("scaffold: parse template index %s: %w", p.IndexRef, err)
	}
	if idx.Kind != trustedsource.TemplateIndexKind {
		return nil, fmt.Errorf("scaffold: index %s has kind %s", p.IndexRef, idx.Kind)
	}
	if err := p.Verifier.VerifyIndex(ctx, p.Source, artifactadmission.ArtifactDescriptor{
		Ref: p.IndexRef, Digest: indexArtifact.Digest, MediaType: trustedsource.TemplateIndexMediaType,
		SourceSHA: idx.SourceSHA, Producer: idx.Producer,
	}); err != nil {
		return nil, fmt.Errorf("scaffold: verify template index %s: %w", p.IndexRef, err)
	}
	var out []catalog.Package
	nextByID := map[string]*TemplatePackage{}
	for _, entry := range idx.Templates {
		ref := templateImmutableRef(entry.OCIRef, entry.Digest)
		descriptor := artifactadmission.ArtifactDescriptor{
			Ref: ref, Digest: entry.Digest, MediaType: entry.MediaType, SourceSHA: entry.SourceSHA,
			ReleaseTag: entry.ReleaseTag, PackageVersion: entry.PackageVersion,
			App: p.Source.ID, Component: entry.Name, Producer: entry.Producer,
			Lanes: entry.Lanes, Compatibility: entry.Compatibility, Runtime: entry.Runtime,
		}
		if _, err := p.Verifier.AdmitArtifact(ctx, artifactadmission.Request{
			Source: p.Source, Role: trustedsource.ArtifactTemplate, Artifact: descriptor,
			TargetEnvironment: trustedsource.EnvironmentDevelopment, SyncOnly: true,
		}); err != nil {
			return nil, fmt.Errorf("scaffold: verify template %s (%s): %w", entry.Name, ref, err)
		}
		artifact, err := p.fetcher().Fetch(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("scaffold: pull template %s (%s): %w", entry.Name, ref, err)
		}
		pkg, manifestRaw, err := p.extractAndValidate(entry.Name, artifact)
		if err != nil {
			return nil, err
		}
		nextByID[entry.Name+"@"+pkg.Manifest.Version] = pkg
		out = append(out, catalog.Package{
			Name: entry.Name, DisplayName: pkg.Manifest.DisplayName, Description: pkg.Manifest.Description,
			Type: "template", Version: pkg.Manifest.Version, Channel: entry.Channel,
			OCIRef: ref, Entry: entry, IndexDigest: indexArtifact.Digest,
			ManifestJSON: manifestRaw, SkeletonDigest: pkg.SkeletonDigest,
			Schema: pkg.Schema, UIHints: pkg.UIHints,
		})
	}
	p.mu.Lock()
	p.byID = nextByID
	p.mu.Unlock()
	return out, nil
}

// Pull implements TemplateSource for existing callers; it syncs the current
// source once and memoizes packages by name@version.
func (p *RegistryTemplateSource) Pull(ctx context.Context) ([]TemplatePackage, error) {
	if _, err := p.pullCatalog(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	keys := make([]string, 0, len(p.byID))
	for key := range p.byID {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]TemplatePackage, 0, len(keys))
	for _, key := range keys {
		out = append(out, *p.byID[key])
	}
	return out, nil
}

// Get implements TemplateSource without refreshing a mutable index. Use Pull
// for an intentional sync, or GetArtifact for an exact run digest.
func (p *RegistryTemplateSource) Get(_ context.Context, name, version string) (*TemplatePackage, error) {
	if name == "" || name != filepath.Base(name) {
		return nil, fmt.Errorf("scaffold: invalid template name %q", name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pkg := p.byID[name+"@"+version]
	if pkg == nil {
		return nil, fmt.Errorf("scaffold: template %s version %s is not in the last synced source", name, version)
	}
	return pkg, nil
}

// GetArtifact resolves one exact OCI template artifact. The caller has
// already admitted this exact ref/digest through catalog.AdmitVersion.
func (p *RegistryTemplateSource) GetArtifact(ctx context.Context, ref, version, expectedSkeletonDigest string) (*TemplatePackage, error) {
	if p.CacheDir == "" {
		return nil, errors.New("scaffold: OCI template source needs a cache dir (INARI_SCAFFOLD_TEMPLATE_CACHE_DIR)")
	}
	name := filepath.Base(templateRepository(ref))
	if name == "" || name == "." || name == "/" {
		return nil, fmt.Errorf("scaffold: invalid template artifact ref %q", ref)
	}
	digest := ""
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		digest = ref[at+1:]
	}
	if digest == "" {
		return nil, fmt.Errorf("scaffold: template ref %q is not digest-pinned", ref)
	}
	digestDir := strings.NewReplacer(":", "-", "/", "-").Replace(digest)
	dir := filepath.Join(p.CacheDir, name, digestDir)
	if _, err := os.Stat(filepath.Join(dir, ".extracted")); err != nil {
		artifact, err := p.fetcher().Fetch(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("scaffold: pull exact template %s: %w", ref, err)
		}
		if artifact.Digest != digest {
			return nil, fmt.Errorf("scaffold: template digest mismatch for %s", ref)
		}
		if err := p.extract(name, dir, artifact); err != nil {
			return nil, err
		}
	}
	pkg, err := readTemplateDir(dir, name)
	if err != nil {
		return nil, err
	}
	if pkg.Manifest.Version != version {
		return nil, fmt.Errorf("scaffold: template %s version %s does not match manifest %s", name, version, pkg.Manifest.Version)
	}
	if expectedSkeletonDigest != "" && pkg.SkeletonDigest != expectedSkeletonDigest {
		return nil, fmt.Errorf("scaffold: template %s skeleton digest mismatch", name)
	}
	return pkg, nil
}

func (p *RegistryTemplateSource) extractAndValidate(name string, artifact *oci.Artifact) (*TemplatePackage, []byte, error) {
	if p.CacheDir == "" {
		return nil, nil, errors.New("scaffold: OCI template source needs a cache dir (INARI_SCAFFOLD_TEMPLATE_CACHE_DIR)")
	}
	digestDir := strings.NewReplacer(":", "-", "/", "-").Replace(artifact.Digest)
	dir := filepath.Join(p.CacheDir, name, digestDir)
	if _, err := os.Stat(filepath.Join(dir, ".extracted")); err != nil {
		if err := p.extract(name, dir, artifact); err != nil {
			return nil, nil, err
		}
	}
	pkg, err := readTemplateDir(dir, name)
	if err != nil {
		return nil, nil, err
	}
	manifestRaw, err := os.ReadFile(filepath.Join(dir, "template.yaml"))
	if err != nil {
		return nil, nil, err
	}
	return pkg, manifestRaw, nil
}

func (p *RegistryTemplateSource) extract(name, dir string, artifact *oci.Artifact) error {
	if name == "" || name != filepath.Base(name) {
		return fmt.Errorf("scaffold: invalid template name %q", name)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for rel, raw := range artifact.Files {
		clean := filepath.Clean(rel)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("scaffold: template layer name %q escapes the package dir", rel)
		}
		dst := filepath.Join(dir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, ".extracted"), []byte(artifact.Digest), 0o644)
}

func templateRepository(ref string) string {
	ref = strings.TrimPrefix(ref, "oci://")
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		ref = ref[:colon]
	}
	return ref
}

func templateImmutableRef(ref, digest string) string {
	return templateRepository(ref) + "@" + digest
}
