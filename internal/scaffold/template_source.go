// Package scaffold implements the M8 software-template machinery: template
// sources (this file), and in later waves the run lifecycle.
package scaffold

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/types"
)

// TemplateManifest mirrors <template>/template.yaml. The Scaffold block
// carries per-phase params (createRepo, createPipeline, registerCatalog,
// bindRBAC) consumed by the run executor in a later wave; it is kept
// permissive (phase name → param map) and only validated for shape here.
type TemplateManifest struct {
	Name        string   `yaml:"name" json:"name"`
	DisplayName string   `yaml:"displayName" json:"displayName,omitempty"`
	Description string   `yaml:"description" json:"description,omitempty"`
	Tags        []string `yaml:"tags" json:"tags,omitempty"`
	Version     string   `yaml:"version" json:"version"`
	Channel     string   `yaml:"channel" json:"channel,omitempty"`
	// Scaffold maps phase name → phase params.
	Scaffold map[string]map[string]any `yaml:"scaffold" json:"scaffold,omitempty"`
}

// TemplatePackage is one parsed software-template package pulled from the
// template dir.
type TemplatePackage struct {
	Manifest TemplateManifest
	// Schema is the raw OpenAPI v3 schema (schema.json) for the run
	// parameters form.
	Schema json.RawMessage
	// UIHints is the raw uiSchema.json (optional).
	UIHints json.RawMessage
	// SkeletonDigest is a content-addressed digest ("sha256:...") of the
	// skeleton/ file tree; skeleton bytes stay on disk.
	SkeletonDigest string
	// Dir is the absolute template directory (for file:// refs).
	Dir string
}

// FilePuller reads template packages from a local directory (the
// INARI_SCAFFOLD_TEMPLATE_DIR layout):
//
//	<root>/<template>/template.yaml   (manifest)
//	<root>/<template>/schema.json     (OpenAPI v3 schema)
//	<root>/<template>/uiSchema.json   (optional)
//	<root>/<template>/skeleton/       (file tree rendered at run time)
//
// Like catalog.FixturePuller it fails fast: one invalid template fails the
// whole pull.
type FilePuller struct {
	Root string
}

// Pull reads every template subdir under Root, sorted by name.
func (p *FilePuller) Pull(_ context.Context) ([]TemplatePackage, error) {
	entries, err := os.ReadDir(p.Root)
	if err != nil {
		return nil, fmt.Errorf("scaffold: read template root: %w", err)
	}
	var out []TemplatePackage
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkg, err := readTemplateDir(filepath.Join(p.Root, e.Name()), e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, *pkg)
	}
	return out, nil
}

func readTemplateDir(dir, dirName string) (*TemplatePackage, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "template.yaml"))
	if err != nil {
		return nil, fmt.Errorf("scaffold: %s: template.yaml: %w", dirName, err)
	}
	var m TemplateManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("scaffold: %s: template.yaml: %w", dirName, err)
	}
	if m.Name == "" {
		m.Name = dirName
	}
	// The render step locates the package on disk by the catalog item ID
	// (which the sync keys by manifest name), so the manifest name must
	// match the directory name exactly and be a single safe path segment.
	if m.Name != dirName {
		return nil, fmt.Errorf("scaffold: %s: template.yaml: name %q must match the template directory name", dirName, m.Name)
	}
	if m.Name != filepath.Base(m.Name) {
		return nil, fmt.Errorf("scaffold: %s: template.yaml: name %q must not contain path separators", dirName, m.Name)
	}
	if m.Version == "" {
		return nil, fmt.Errorf("scaffold: %s: template.yaml: version is required", dirName)
	}
	if m.Channel == "" {
		m.Channel = "stable"
	}
	schema, err := readJSONFile(dir, "schema.json", true)
	if err != nil {
		return nil, fmt.Errorf("scaffold: %s: %w", dirName, err)
	}
	uiHints, err := readJSONFile(dir, "uiSchema.json", false)
	if err != nil {
		return nil, fmt.Errorf("scaffold: %s: %w", dirName, err)
	}
	digest, err := skeletonDigest(filepath.Join(dir, "skeleton"))
	if err != nil {
		return nil, fmt.Errorf("scaffold: %s: %w", dirName, err)
	}
	return &TemplatePackage{
		Manifest:       m,
		Schema:         schema,
		UIHints:        uiHints,
		SkeletonDigest: digest,
		Dir:            dir,
	}, nil
}

// readJSONFile reads dir/name and validates it is well-formed JSON. When
// required is false a missing file yields nil without error.
func readJSONFile(dir, name string, required bool) (json.RawMessage, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if !required && os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", name, err)
	}
	return raw, nil
}

// skeletonDigest computes a sha256 over the sorted (relpath, file-sha256)
// pairs of the tree rooted at dir. The tree must exist and contain at least
// one file.
func skeletonDigest(dir string) (string, error) {
	type entry struct {
		rel  string
		hash string
	}
	var entries []entry
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		entries = append(entries, entry{rel: filepath.ToSlash(rel), hash: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("skeleton: %w", err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("skeleton: tree is empty")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		h.Write([]byte(e.rel))
		h.Write([]byte{0})
		h.Write([]byte(e.hash))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// CatalogUpserter is the slice of catalog.Service the template sync needs;
// *catalog.Service satisfies it.
type CatalogUpserter interface {
	UpsertItem(ctx context.Context, item *types.CatalogItem, version *types.CatalogItemVersion) error
}

// templateSyncPlan turns pulled template packages into catalog item/version
// upserts: item ID "template:<name>", source types.CatalogSourceTemplate,
// payload = manifest + skeleton digest. Pure — kept separate from
// SyncTemplates so tests can assert the mapping without a database (mirrors
// catalog's syncPlan).
func templateSyncPlan(pkgs []TemplatePackage) ([]*types.CatalogItem, []*types.CatalogItemVersion, error) {
	items := make([]*types.CatalogItem, 0, len(pkgs))
	versions := make([]*types.CatalogItemVersion, 0, len(pkgs))
	for _, p := range pkgs {
		itemID := "template:" + p.Manifest.Name
		payload, err := json.Marshal(map[string]any{
			"manifest":       p.Manifest,
			"skeletonDigest": p.SkeletonDigest,
		})
		if err != nil {
			return nil, nil, err
		}
		items = append(items, &types.CatalogItem{
			ID:          itemID,
			Source:      types.CatalogSourceTemplate,
			Name:        p.Manifest.Name,
			DisplayName: p.Manifest.DisplayName,
			Description: p.Manifest.Description,
			OCIRef:      fmt.Sprintf("file://%s:%s", p.Dir, p.Manifest.Version),
		})
		versions = append(versions, &types.CatalogItemVersion{
			ItemID:  itemID,
			Version: p.Manifest.Version,
			Channel: p.Manifest.Channel,
			Schema:  p.Schema,
			UIHints: p.UIHints,
			Payload: payload,
		})
	}
	return items, versions, nil
}

// SyncTemplates pulls template packages and upserts them into the catalog
// (one item per template, one version row per package). Idempotent.
func SyncTemplates(ctx context.Context, puller *FilePuller, up CatalogUpserter) (int, error) {
	pkgs, err := puller.Pull(ctx)
	if err != nil {
		return 0, err
	}
	items, versions, err := templateSyncPlan(pkgs)
	if err != nil {
		return 0, err
	}
	count := 0
	for i := range items {
		if err := up.UpsertItem(ctx, items[i], versions[i]); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
