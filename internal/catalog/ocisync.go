package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/oci"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ChartRef carries the Helm chart coordinates of a platform-app package
// (from the package's chart.yaml).
type ChartRef struct {
	RepoURL   string `json:"repoURL"`
	Chart     string `json:"chart"`
	Namespace string `json:"namespace"`
	OCIRef    string `json:"ociRef"`
	Digest    string `json:"digest"`
}

// Package is one curated package version pulled from the catalog registry.
type Package struct {
	Name        string
	DisplayName string
	Description string
	// Type is the package.yaml/index type: "platform-app", "kro-rgd",
	// "policy-pack". Empty behaves as "kro-rgd".
	Type     string
	Version  string
	Channel  string
	Category string
	// OCIRef is the immutable image reference this package version was pulled from.
	OCIRef string
	// Entry is the signed index entry used for later deploy/render admission.
	Entry       trustedsource.IndexEntry
	IndexDigest string
	// Chart is set for platform-app packages.
	Chart *ChartRef
	// RGD is the raw KRO ResourceGraphDefinition YAML.
	RGD []byte
	// Template metadata is used only by software-template sources.
	ManifestJSON   []byte
	SkeletonDigest string
	// Schema is the OpenAPI v3 schema for the instance form; when absent it
	// is derived from the RGD's generated CRD spec at deploy time.
	Schema  []byte
	UIHints []byte
}

// itemIDForPackage maps a pulled package to its canonical server-assigned
// source-qualified ID. Index metadata cannot replace this identity.
func itemIDForPackage(sourceID string, p Package) string {
	return sourceID + "/" + p.Name
}

// sourceForPackage preserves the seeded platform source for platform apps.
func sourceForPackage(p Package) types.CatalogSource {
	if p.Type == "platform-app" {
		return types.CatalogSourcePlatform
	}
	if p.Type == "template" {
		return types.CatalogSourceTemplate
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
	Category    string `json:"category"`
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
	RepoURL   string                  `yaml:"repoURL"`
	Chart     string                  `yaml:"chart"`
	Namespace string                  `yaml:"namespace"`
	Channels  map[string]chartChannel `yaml:"channels"`
}

type chartChannel struct {
	Version string `yaml:"version"`
	OCIRef  string `yaml:"ociRef"`
	Digest  string `yaml:"digest"`
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
//	<root>/<package>/<version>/values.schema.json (optional vendored chart values schema)
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
	pkg.Category = meta.Category
	if pkg.RGD, err = os.ReadFile(filepath.Join(dir, "rgd.yaml")); err != nil {
		return nil, fmt.Errorf("catalog: %s: rgd.yaml: %w", dir, err)
	}
	pkg.Schema, _ = os.ReadFile(filepath.Join(dir, "schema.json"))
	// Platform-app packages vendor the upstream chart's values.schema.json
	// (day-one adopt/update validation, decision 4); use it when no
	// schema.json instance schema exists.
	if len(pkg.Schema) == 0 {
		pkg.Schema, _ = os.ReadFile(filepath.Join(dir, "values.schema.json"))
	}
	pkg.UIHints, _ = os.ReadFile(filepath.Join(dir, "ui-hints.json"))
	return &pkg, nil
}

// RegistryPuller pulls the real curated packages from an OCI registry. It
// first fetches the catalog index artifact (an oras-pushed catalog.yaml,
// e.g. ghcr.io/7k-inari/catalog/index:latest), then each package artifact
// listed in it. inari-catalog's release.yml publishes both: per-package
// artifacts on every package release and the index artifact afterwards.
type RegistryPuller struct {
	// IndexRef is the OCI reference of the catalog index artifact.
	IndexRef string
	Source   trustedsource.Source
	Verifier *artifactadmission.Verifier
	// Keychain overrides registry auth (default: authn.DefaultKeychain).
	Keychain authn.Keychain
	// Insecure allows plain-HTTP registries (tests/dev).
	Insecure bool
}

func (p *RegistryPuller) fetcher() *oci.Fetcher {
	return &oci.Fetcher{Keychain: p.Keychain, Insecure: p.Insecure}
}

func (p *RegistryPuller) Pull(ctx context.Context) ([]Package, error) {
	if p.Verifier == nil {
		return nil, errors.New("catalog: trusted source verifier is required")
	}
	indexArtifact, err := p.fetcher().Fetch(ctx, p.IndexRef)
	if err != nil {
		return nil, fmt.Errorf("catalog: pull index %s: %w", p.IndexRef, err)
	}
	indexRaw, ok := indexArtifact.Files["catalog.yaml"]
	if !ok {
		return nil, fmt.Errorf("catalog: index %s has no catalog.yaml layer", p.IndexRef)
	}
	idx, err := trustedsource.DecodeIndex(indexRaw)
	if err != nil {
		return nil, fmt.Errorf("catalog: parse index %s: %w", p.IndexRef, err)
	}
	if idx.Kind != trustedsource.CatalogIndexKind {
		return nil, fmt.Errorf("catalog: index %s has kind %s", p.IndexRef, idx.Kind)
	}
	indexDescriptor := artifactadmission.ArtifactDescriptor{
		Ref: p.IndexRef, Digest: indexArtifact.Digest, MediaType: trustedsource.CatalogIndexMediaType,
		SourceSHA: idx.SourceSHA, Producer: idx.Producer,
	}
	if err := p.Verifier.VerifyIndex(ctx, p.Source, indexDescriptor); err != nil {
		return nil, fmt.Errorf("catalog: verify index %s: %w", p.IndexRef, err)
	}
	var out []Package
	for _, entry := range idx.Packages {
		ref := immutableOCIRef(entry.OCIRef, entry.Digest)
		descriptor := artifactadmission.ArtifactDescriptor{
			Ref: ref, Digest: entry.Digest, MediaType: entry.MediaType, SourceSHA: entry.SourceSHA,
			ReleaseTag: entry.ReleaseTag, PackageVersion: entry.PackageVersion,
			App: p.Source.ID, Component: entry.Name, Producer: entry.Producer,
			Lanes: entry.Lanes, Compatibility: entry.Compatibility, Runtime: entry.Runtime,
		}
		if _, err := p.Verifier.AdmitArtifact(ctx, artifactadmission.Request{
			Source: p.Source, Role: trustedsource.ArtifactCatalogPackage, Artifact: descriptor, TargetEnvironment: trustedsource.EnvironmentDevelopment, SyncOnly: true,
		}); err != nil {
			return nil, fmt.Errorf("catalog: verify package %s (%s): %w", entry.Name, ref, err)
		}
		if entry.Type == "platform-app" {
			chartDescriptor := descriptor
			chartDescriptor.Ref = entry.ChartRef
			chartDescriptor.Digest = entry.ChartDigest
			chartDescriptor.MediaType = trustedsource.HelmChartMediaType
			chartDescriptor.Producer = *entry.ChartProducer
			if _, err := p.Verifier.AdmitArtifact(ctx, artifactadmission.Request{
				Source: p.Source, Role: trustedsource.ArtifactHelmChart, Artifact: chartDescriptor, TargetEnvironment: trustedsource.EnvironmentDevelopment, SyncOnly: true,
			}); err != nil {
				return nil, fmt.Errorf("catalog: verify chart for %s (%s): %w", entry.Name, entry.ChartRef, err)
			}
		}
		files, err := p.fetchDir(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("catalog: pull package %s (%s): %w", entry.Name, ref, err)
		}
		pkgs, err := packageFromFiles(entry.Name, entry.Type, entry.Description, ref, files)
		if err != nil {
			return nil, err
		}
		for i := range pkgs {
			pkgs[i].Entry = entry
			pkgs[i].IndexDigest = indexArtifact.Digest
			pkgs[i].OCIRef = ref
		}
		out = append(out, pkgs...)
	}
	return out, nil
}

func immutableOCIRef(ref, digest string) string {
	repository := ref
	if at := strings.Index(repository, "@"); at >= 0 {
		repository = repository[:at]
	} else if colon := strings.LastIndex(repository, ":"); colon > strings.LastIndex(repository, "/") {
		repository = repository[:colon]
	}
	return repository + "@" + digest
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
		base.Category = py.Category
	}
	base.Schema = files["schema.json"]
	// Platform-app packages vendor the upstream chart's values.schema.json
	// (day-one adopt/update validation, decision 4); use it when no
	// schema.json layer exists.
	if len(base.Schema) == 0 {
		base.Schema = files["values.schema.json"]
	}
	// Packages ship no schema.json layer; fall back to deriving the instance
	// schema from the RGD's spec.schema so item previews/deploy forms render.
	if len(base.Schema) == 0 {
		if raw, ok := files["rgd.yaml"]; ok {
			if schema, err := schemaFromRGD(raw); err == nil && len(schema) > 0 {
				base.Schema = schema
			}
		}
	}
	base.UIHints = files["ui-hints.json"]
	// inari-catalog packages ship ui-hints.yaml; convert to JSON for the
	// jsonb column / API responses.
	if len(base.UIHints) == 0 {
		if raw, ok := files["ui-hints.yaml"]; ok {
			var hints any
			if err := yaml.Unmarshal(raw, &hints); err == nil {
				if asJSON, err := json.Marshal(hints); err == nil {
					base.UIHints = asJSON
				}
			}
		}
	}
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
			channel := cy.Channels[ch]
			pkg.Channel = ch
			pkg.Version = channel.Version
			pkg.Chart.OCIRef = channel.OCIRef
			pkg.Chart.Digest = channel.Digest
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
func syncPlan(sourceID string, pkgs []Package) ([]*types.CatalogItem, []*types.CatalogItemVersion, error) {
	items := make([]*types.CatalogItem, 0, len(pkgs))
	versions := make([]*types.CatalogItemVersion, 0, len(pkgs))
	for _, p := range pkgs {
		// Defense against unusable rows: a package without a version can
		// never be deployed and renders as an empty '' row in every view
		// (live incident, 2026-09-12). Skip it rather than poison the
		// catalog — the sync summary still reports the other packages.
		if p.Version == "" {
			slog.Warn("catalog sync: skipping package with empty version", "name", p.Name, "ref", p.OCIRef)
			continue
		}
		if p.Entry.SourceSHA == "" {
			p.Entry.SourceSHA = "0000000000000000000000000000000000000000"
		}
		if p.Entry.Digest == "" {
			sum := sha256.Sum256([]byte(p.Name + "@" + p.Version))
			p.Entry.Digest = "sha256:" + hex.EncodeToString(sum[:])
		}
		if p.Entry.MediaType == "" {
			p.Entry.MediaType = trustedsource.CatalogPackageMediaType
		}
		itemID := itemIDForPackage(sourceID, p)
		payload := map[string]any{
			"admission": p.Entry,
		}
		if p.Type == "template" {
			payload["manifest"] = json.RawMessage(p.ManifestJSON)
			payload["skeletonDigest"] = p.SkeletonDigest
		}
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
			ID:              itemID,
			Source:          sourceForPackage(p),
			SourceID:        sourceID,
			Name:            p.Name,
			DisplayName:     p.DisplayName,
			Description:     p.Description,
			Category:        p.Category,
			OCIRef:          ociRef,
			SnapshotPresent: true,
		})
		packageVersion := p.Entry.PackageVersion
		if packageVersion == "" {
			packageVersion = p.Version
		}
		versions = append(versions, &types.CatalogItemVersion{
			ItemID:          itemID,
			Version:         p.Version,
			PackageVersion:  packageVersion,
			Channel:         p.Channel,
			ArtifactRef:     ociRef,
			ArtifactDigest:  p.Entry.Digest,
			SnapshotPresent: true,
			Schema:          p.Schema,
			UIHints:         p.UIHints,
			Payload:         raw,
		})
		if p.Chart != nil {
			versions[len(versions)-1].ChartRef = p.Chart.OCIRef
			versions[len(versions)-1].ChartDigest = p.Chart.Digest
		}
	}
	return items, versions, nil
}

// Sync pulls and atomically replaces every configured source independently.
// A failed source records its own status and cannot block another source's
// valid generation. All errors are returned for observability.
func (s *Service) Sync(ctx context.Context) (int, error) {
	return s.SyncKind(ctx, "")
}

func (s *Service) SyncKind(ctx context.Context, kind string) (int, error) {
	if len(s.sources) == 0 {
		return 0, ErrSyncNotConfigured
	}
	total := 0
	matched := 0
	var syncErrors []error
	for _, sourceSync := range s.sources {
		if kind != "" && sourceSync.Kind != "" && sourceSync.Kind != kind {
			continue
		}
		matched++
		count, err := s.syncOne(ctx, sourceSync)
		total += count
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("%s %s: %w", sourceSync.Kind, sourceSync.Source.ID, err))
		}
	}
	if matched == 0 {
		return 0, ErrSyncNotConfigured
	}
	return total, errors.Join(syncErrors...)
}

func (s *Service) syncOne(ctx context.Context, sourceSync SourceSync) (count int, returnErr error) {
	source := sourceSync.Source
	kind := sourceSync.Kind
	if kind == "" {
		kind = "catalog"
	}
	fingerprint, err := (&trustedsource.File{}).Fingerprint(source)
	if err != nil {
		return 0, err
	}
	defer func() {
		if returnErr != nil {
			code := "sync_failed"
			var admissionErr *artifactadmission.Error
			if errors.As(returnErr, &admissionErr) {
				code = admissionErr.Code
			}
			if err := s.store.RecordSourceFailure(ctx, s.db.Pool, kind, source, fingerprint, code, returnErr, s.now()); err != nil {
				slog.Error("trusted source failure status write failed", "source", source.ID, "error", err)
			}
		}
	}()
	pkgs, err := sourceSync.Puller.Pull(ctx)
	if err != nil {
		return 0, err
	}
	items, versions, err := syncPlan(source.ID, pkgs)
	if err != nil {
		return 0, err
	}
	replacement := SourceReplacement{
		Kind: kind, Source: source, Fingerprint: fingerprint, Items: items, Versions: versions,
		LastGoodIndexRef: source.IndexRef, Now: s.now(),
	}
	if len(pkgs) > 0 {
		replacement.IndexDigest = pkgs[0].IndexDigest
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.ReplaceSource(ctx, tx, replacement); err != nil {
			return err
		}
		for _, item := range items {
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: "platform", Actor: "system:catalog-sync", Action: "catalog.item_upserted",
				ObjectType: "catalog_item", ObjectID: item.ID,
			}); err != nil {
				return err
			}
			if err := audit.AppendOutbox(ctx, tx, "platform", types.EventCatalogItemUpserted, types.CatalogItemPayload{
				OrgID: item.OrgID, ItemID: item.ID, Source: string(item.Source),
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(items), nil
}

func (s *Service) ListTrustedSourceStates(ctx context.Context, kind string) ([]types.TrustedSourceStatus, error) {
	return s.store.ListTrustedSourceStates(ctx, s.db.Pool, kind, s.now())
}

func (s *Service) ReconcileSourcePolicies(ctx context.Context, kind string, expected map[string]string) error {
	return s.store.ReconcileSourcePolicies(ctx, s.db.Pool, kind, expected)
}
