package scaffold

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	IndexRef    string
	Source      trustedsource.Source
	Verifier    *artifactadmission.Verifier
	CacheDir    string
	Keychain    authn.Keychain
	Insecure    bool
	Environment trustedsource.Environment

	mu          sync.Mutex
	byID        map[string]*TemplatePackage
	indexDigest string
}

func (p *RegistryTemplateSource) LastIndexDigest() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.indexDigest
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
	}, p.Environment); err != nil {
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
			TargetEnvironment: p.Environment, SyncOnly: true,
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
		if pkg.Manifest.Version != entry.Version || pkg.Manifest.Version != entry.PackageVersion {
			return nil, fmt.Errorf("scaffold: template %s manifest version %q does not match signed index version/packageVersion %q/%q", entry.Name, pkg.Manifest.Version, entry.Version, entry.PackageVersion)
		}
		if pkg.Manifest.Channel != entry.Channel {
			return nil, fmt.Errorf("scaffold: template %s manifest channel %q does not match signed index channel %q", entry.Name, pkg.Manifest.Channel, entry.Channel)
		}
		nextByID[entry.Name+"@"+pkg.Manifest.Version] = pkg
		out = append(out, catalog.Package{
			Name: entry.Name, DisplayName: pkg.Manifest.DisplayName, Description: pkg.Manifest.Description,
			Type: "template", Version: pkg.Manifest.Version, Channel: entry.Channel,
			OCIRef: ref, Entry: entry, IndexDigest: indexArtifact.Digest,
			ManifestJSON: manifestRaw, SkeletonDigest: pkg.SkeletonDigest, ApprovalPolicy: approvalPolicyFor(pkg.Manifest.Scaffold),
			Observability: pkg.Observability, Schema: pkg.Schema, UIHints: pkg.UIHints,
		})
	}
	p.mu.Lock()
	p.byID = nextByID
	p.indexDigest = indexArtifact.Digest
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
func (p *RegistryTemplateSource) GetArtifact(ctx context.Context, ref, version, expectedSkeletonDigest string, expectedManifest []byte) (*TemplatePackage, error) {
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
	if len(expectedManifest) > 0 {
		manifest, err := json.Marshal(pkg.Manifest)
		if err != nil {
			return nil, fmt.Errorf("scaffold: encode template manifest %s: %w", name, err)
		}
		if !bytes.Equal(manifest, expectedManifest) {
			return nil, fmt.Errorf("scaffold: template %s manifest digest mismatch", name)
		}
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
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("scaffold: inspect template cache %s: %w", dir, err)
		}
		if err := p.extract(name, dir, artifact); err != nil {
			return nil, nil, err
		}
	}
	if err := verifyTemplateCache(dir, artifact.Digest, artifact.Files); err != nil {
		return nil, nil, err
	}
	pkg, err := readTemplateDir(dir, name)
	if err != nil {
		return nil, nil, err
	}
	manifestRaw, err := json.Marshal(pkg.Manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("scaffold: encode template manifest %s: %w", name, err)
	}
	return pkg, manifestRaw, nil
}

// verifyTemplateCache binds the complete on-disk extraction to the artifact
// bytes verified during this sync. Marker presence alone is never sufficient:
// altered files, unexpected files, missing files, links, and marker spoofing
// all fail before a snapshot can be persisted.
func verifyTemplateCache(dir, digest string, expected map[string][]byte) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("scaffold: inspect template cache %s: %w", dir, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("scaffold: template cache %s is not a real directory", dir)
	}
	seen := make(map[string]bool, len(expected))
	markerSeen := false
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("scaffold: template cache contains non-regular entry %q", rel)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if rel == ".extracted" {
			if info.Size() != int64(len(digest)) {
				return fmt.Errorf("scaffold: template cache marker digest mismatch")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if string(raw) != digest {
				return fmt.Errorf("scaffold: template cache marker digest mismatch")
			}
			markerSeen = true
			return nil
		}
		want, ok := expected[rel]
		if !ok {
			return fmt.Errorf("scaffold: template cache contains unexpected file %q", rel)
		}
		if info.Size() != int64(len(want)) {
			return fmt.Errorf("scaffold: template cache file %q does not match verified bytes", rel)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, want) {
			return fmt.Errorf("scaffold: template cache file %q does not match verified bytes", rel)
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	if !markerSeen {
		return fmt.Errorf("scaffold: template cache marker is missing")
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("scaffold: template cache is incomplete: got %d of %d verified files", len(seen), len(expected))
	}
	for rel := range expected {
		if !seen[rel] {
			return fmt.Errorf("scaffold: template cache is missing verified file %q", rel)
		}
	}
	return nil
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
