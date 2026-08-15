package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/7K-Inari/inari-server/internal/types"
)

// Package is one curated package version pulled from the catalog registry.
type Package struct {
	Name        string
	DisplayName string
	Description string
	Version     string
	Channel     string
	// RGD is the raw KRO ResourceGraphDefinition YAML.
	RGD []byte
	// Schema is the OpenAPI v3 schema for the instance form; when absent it
	// is derived from the RGD's generated CRD spec at deploy time.
	Schema  []byte
	UIHints []byte
}

// OCIPuller fetches curated packages. Built against a fixture OCI layout at
// M2 (inari-catalog artifacts publish in parallel); a go-containerregistry
// client slots in behind this interface without callers changing.
type OCIPuller interface {
	Pull(ctx context.Context) ([]Package, error)
}

type packageMetadata struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Channel     string `json:"channel"`
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

// ErrSyncNotConfigured is returned when no OCI puller is wired (no
// INARI_CATALOG_OCI_PATH / registry client configured).
var ErrSyncNotConfigured = fmt.Errorf("catalog: sync not configured (no OCI puller)")

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
	count := 0
	for _, p := range pkgs {
		itemID := "curated:" + p.Name
		payload, err := json.Marshal(map[string]string{
			"rgd": string(p.RGD),
		})
		if err != nil {
			return count, err
		}
		item := &types.CatalogItem{
			ID:          itemID,
			Source:      types.CatalogSourceCurated,
			Name:        p.Name,
			DisplayName: p.DisplayName,
			Description: p.Description,
			OCIRef:      "fixture://" + p.Name + ":" + p.Version,
		}
		version := &types.CatalogItemVersion{
			ItemID:  itemID,
			Version: p.Version,
			Channel: p.Channel,
			Schema:  p.Schema,
			UIHints: p.UIHints,
			Payload: payload,
		}
		if err := s.UpsertItem(ctx, item, version); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
