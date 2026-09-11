package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/go-containerregistry/pkg/authn"
	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/oci"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ChartRef carries the Helm chart coordinates of a platform-app package
// (from the package's chart.yaml).
type ChartRef struct {
	RepoURL   string `json:"repoURL"`
	Chart     string `json:"chart"`
	Namespace string `json:"namespace"`
}

// Package is one curated package version pulled from the catalog registry.
type Package struct {
	Name        string
	DisplayName string
	Description string
	// Type is the package.yaml/index type: "platform-app", "kro-rgd",
	// "policy-pack". Empty behaves as "kro-rgd".
	Type    string
	Version string
	Channel string
	// OCIRef is the image reference this package version was pulled from.
	OCIRef string
	// Chart is set for platform-app packages.
	Chart *ChartRef
	// RGD is the raw KRO ResourceGraphDefinition YAML.
	RGD []byte
	// Schema is the OpenAPI v3 schema for the instance form; when absent it
	// is derived from the RGD's generated CRD spec at deploy time.
	Schema  []byte
	UIHints []byte
}

// itemIDForPackage maps a pulled package to its catalog item ID. Platform
// apps reconcile with the items seeded by SeedPlatformApps
// ("platform:<name>", e.g. platform:external-secrets); all other curated
// packages keep the "curated:<name>" prefix. Software-template items (M8
// scaffolding) use the "template:<name>" prefix with the
// types.CatalogSourceTemplate source; they are not written by this sync
// path.
func itemIDForPackage(p Package) string {
	if p.Type == "platform-app" {
		return "platform:" + p.Name
	}
	return "curated:" + p.Name
}

// sourceForPackage preserves the seeded platform source for platform apps.
func sourceForPackage(p Package) types.CatalogSource {
	if p.Type == "platform-app" {
		return types.CatalogSourcePlatform
	}
	return types.CatalogSourceCurated
}

// OCIPuller fetches curated packages. FixturePuller serves tests/dev;
// RegistryPuller pulls the real inari-catalog OCI artifacts.
type OCIPuller interface {
	Pull(ctx context.Context) ([]Package, error)
}

type packageMetadata struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Channel     string `json:"channel"`
}

// packageYAML mirrors packages/<name>/package.yaml in inari-catalog.
type packageYAML struct {
	Version     string `yaml:"version"`
	Channel     string `yaml:"channel"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Category    string `yaml:"category"`
}

// chartYAML mirrors packages/<name>/chart.yaml (platform apps only).
type chartYAML struct {
	RepoURL   string            `yaml:"repoURL"`
	Chart     string            `yaml:"chart"`
	Namespace string            `yaml:"namespace"`
	Channels  map[string]string `yaml:"channels"`
}

// catalogIndex mirrors catalog.yaml in inari-catalog.
type catalogIndex struct {
	Packages []struct {
		Name        string `yaml:"name"`
		Version     string `yaml:"version"`
		Channel     string `yaml:"channel"`
		Type        string `yaml:"type"`
		Description string `yaml:"description"`
		OCIRef      string `yaml:"ociRef"`
		ChannelRef  string `yaml:"channelRef"`
	} `yaml:"packages"`
}

// FixturePuller reads a local OCI-style layout:
//
//	<root>/<package>/<version>/metadata.json   (name, displayName, channel)
//	<root>/<package>/<version>/rgd.yaml        (KRO RGD)
//	<root>/<package>/<version>/schema.json     (optional OpenAPI v3 schema)
//	<root>/<package>/<version>/ui-hints.json   (optional)
type FixturePuller struct {
	Root string
}

func (p *FixturePuller) Pull(_ context.Context) ([]Package, error) {
	var out []Package
	names, err := os.ReadDir(p.Root)
	if err != nil {
		return nil, fmt.Errorf("catalog: read fixture root: %w", err)
	}
	for _, n := range names {
		if !n.IsDir() {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(p.Root, n.Name()))
		if err != nil {
			return nil, err
		}
		for _, v := range versions {
			if !v.IsDir() {
				continue
			}
			dir := filepath.Join(p.Root, n.Name(), v.Name())
			pkg, err := readPackageDir(dir)
			if err != nil {
				return nil, err
			}
			if pkg.Name == "" {
				pkg.Name = n.Name()
			}
			pkg.Version = v.Name()
			if pkg.Channel == "" {
				pkg.Channel = "stable"
			}
			out = append(out, *pkg)
		}
	}
	return out, nil
}

func readPackageDir(dir string) (*Package, error) {
	var pkg Package
	raw, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		return nil, fmt.Errorf("catalog: %s: metadata.json: %w", dir, err)
	}
	var meta packageMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("catalog: %s: metadata.json: %w", dir, err)
	}
	pkg.Name = meta.Name
	pkg.DisplayName = meta.DisplayName
	pkg.Description = meta.Description
	pkg.Channel = meta.Channel
	if pkg.RGD, err = os.ReadFile(filepath.Join(dir, "rgd.yaml")); err != nil {
		return nil, fmt.Errorf("catalog: %s: rgd.yaml: %w", dir, err)
	}
	pkg.Schema, _ = os.ReadFile(filepath.Join(dir, "schema.json"))
	pkg.UIHints, _ = os.ReadFile(filepath.Join(dir, "ui-hints.json"))
	return &pkg, nil
}

// RegistryPuller pulls the real curated packages from an OCI registry. It
// first fetches the catalog index artifact (an oras-pushed catalog.yaml,
// e.g. ghcr.io/7k-inari/catalog/index:latest), then each package artifact
// listed in it. inari-catalog pushes per-package artifacts today; publishing
// the index artifact is the companion step on that repo.
type RegistryPuller struct {
	// IndexRef is the OCI reference of the catalog index artifact.
	IndexRef string
	// Keychain overrides registry auth (default: authn.DefaultKeychain).
	Keychain authn.Keychain
	// Insecure allows plain-HTTP registries (tests/dev).
	Insecure bool
}

func (p *RegistryPuller) fetcher() *oci.Fetcher {
	return &oci.Fetcher{Keychain: p.Keychain, Insecure: p.Insecure}
}

func (p *RegistryPuller) Pull(ctx context.Context) ([]Package, error) {
	indexRaw, err := p.fetchFile(ctx, p.IndexRef, "catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("catalog: pull index %s: %w", p.IndexRef, err)
	}
	var idx catalogIndex
	if err := yaml.Unmarshal(indexRaw, &idx); err != nil {
		return nil, fmt.Errorf("catalog: parse index %s: %w", p.IndexRef, err)
	}
	var out []Package
	for _, entry := range idx.Packages {
		ref := entry.ChannelRef
		if ref == "" {
			ref = entry.OCIRef
		}
		if ref == "" {
			return nil, fmt.Errorf("catalog: index package %q has no ociRef", entry.Name)
		}
		files, err := p.fetchDir(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("catalog: pull package %s (%s): %w", entry.Name, ref, err)
		}
		pkgs, err := packageFromFiles(entry.Name, entry.Type, entry.Description, ref, files)
		if err != nil {
			return nil, err
		}
		out = append(out, pkgs...)
	}
	return out, nil
}

// fetchFile pulls an oras-style artifact and returns the content of the
// layer titled filename.
func (p *RegistryPuller) fetchFile(ctx context.Context, ref, filename string) ([]byte, error) {
	files, err := p.fetchDir(ctx, ref)
	if err != nil {
		return nil, err
	}
	raw, ok := files[filename]
	if !ok {
		return nil, fmt.Errorf("catalog: %s: no layer named %q", ref, filename)
	}
	return raw, nil
}

// fetchDir pulls an oras directory-push artifact (shared helper).
func (p *RegistryPuller) fetchDir(ctx context.Context, ref string) (map[string][]byte, error) {
	return p.fetcher().FetchDir(ctx, ref)
}

// packageFromFiles builds Packages from one pulled package artifact.
// Platform apps expand chart.yaml channels into one Package per channel
// (the chart version is what deploys resolve); other package types yield a
// single Package at their package.yaml version/channel.
func packageFromFiles(name, typ, indexDesc, ref string, files map[string][]byte) ([]Package, error) {
	base := Package{Name: name, Type: typ, Description: indexDesc, OCIRef: ref}
	if raw, ok := files["package.yaml"]; ok {
		var py packageYAML
		if err := yaml.Unmarshal(raw, &py); err != nil {
			return nil, fmt.Errorf("catalog: %s: package.yaml: %w", ref, err)
		}
		if py.Type != "" {
			base.Type = py.Type
		}
		if base.Description == "" {
			base.Description = py.Description
		}
		base.Version = py.Version
		base.Channel = py.Channel
	}
	base.Schema = files["schema.json"]
	base.UIHints = files["ui-hints.json"]
	if raw, ok := files["chart.yaml"]; ok {
		var cy chartYAML
		if err := yaml.Unmarshal(raw, &cy); err != nil {
			return nil, fmt.Errorf("catalog: %s: chart.yaml: %w", ref, err)
		}
		base.Chart = &ChartRef{RepoURL: cy.RepoURL, Chart: cy.Chart, Namespace: cy.Namespace}
		if len(cy.Channels) == 0 {
			return nil, fmt.Errorf("catalog: %s: chart.yaml has no channels", ref)
		}
		channels := make([]string, 0, len(cy.Channels))
		for ch := range cy.Channels {
			channels = append(channels, ch)
		}
		sort.Strings(channels)
		out := make([]Package, 0, len(channels))
		for _, ch := range channels {
			pkg := base
			pkg.Channel = ch
			pkg.Version = cy.Channels[ch]
			out = append(out, pkg)
		}
		return out, nil
	}
	if raw, ok := files["rgd.yaml"]; ok {
		base.RGD = raw
	}
	if base.Channel == "" {
		base.Channel = "stable"
	}
	return []Package{base}, nil
}

// ErrSyncNotConfigured is returned when no OCI puller is wired (no
// INARI_CATALOG_OCI_INDEX_REF / INARI_CATALOG_OCI_PATH configured).
var ErrSyncNotConfigured = fmt.Errorf("catalog: sync not configured (no OCI puller)")

// syncPlan turns pulled packages into item + version upserts. Pure — kept
// separate from Sync so tests can assert the mapping without a database.
func syncPlan(pkgs []Package) ([]*types.CatalogItem, []*types.CatalogItemVersion, error) {
	items := make([]*types.CatalogItem, 0, len(pkgs))
	versions := make([]*types.CatalogItemVersion, 0, len(pkgs))
	for _, p := range pkgs {
		itemID := itemIDForPackage(p)
		payload := map[string]any{}
		if len(p.RGD) > 0 {
			payload["rgd"] = string(p.RGD)
		}
		if p.Chart != nil {
			payload["chart"] = p.Chart
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		ociRef := p.OCIRef
		if ociRef == "" {
			ociRef = "fixture://" + p.Name + ":" + p.Version
		}
		items = append(items, &types.CatalogItem{
			ID:          itemID,
			Source:      sourceForPackage(p),
			Name:        p.Name,
			DisplayName: p.DisplayName,
			Description: p.Description,
			OCIRef:      ociRef,
		})
		versions = append(versions, &types.CatalogItemVersion{
			ItemID:  itemID,
			Version: p.Version,
			Channel: p.Channel,
			Schema:  p.Schema,
			UIHints: p.UIHints,
			Payload: raw,
		})
	}
	return items, versions, nil
}

// Sync pulls curated packages and upserts them as catalog items (one item
// per package name, one version row per package version). Idempotent.
func (s *Service) Sync(ctx context.Context) (int, error) {
	if s.puller == nil {
		return 0, ErrSyncNotConfigured
	}
	pkgs, err := s.puller.Pull(ctx)
	if err != nil {
		return 0, err
	}
	items, versions, err := syncPlan(pkgs)
	if err != nil {
		return 0, err
	}
	count := 0
	for i := range items {
		if err := s.UpsertItem(ctx, items[i], versions[i]); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
