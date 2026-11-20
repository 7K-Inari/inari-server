package deploymentplan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	observability "github.com/7K-Inari/inari-api/contract/observability/v1"
	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/resourcetargets"
	"github.com/7K-Inari/inari-server/internal/types"
	"gopkg.in/yaml.v3"
)

type normalizedSource struct {
	source           Source
	app              ArtifactPin
	capabilityDigest string
	capability       *observabilityCapability
	managedChart     bool
	item             *types.CatalogItem
	version          *types.CatalogItemVersion
}

// observabilityCapability is an alias used internally to keep the normalized
// source signature readable while exposing the canonical API type on Plan.
type observabilityCapability = observability.Capability

func environmentFor(resolved *resourcetargets.ResolvedTarget) trustedsource.Environment {
	if resolved != nil && resolved.Cluster != nil {
		if environment := trustedsource.Environment(resolved.Cluster.Labels["inari.dev/environment"]); environment != "" {
			return environment
		}
	}
	// Preflight without a selected target uses the strictest environment. A
	// selected development target is resolved before admission on submit.
	return trustedsource.EnvironmentProduction
}

func ociRepository(ref string) string {
	ref = strings.TrimPrefix(ref, "oci://")
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		ref = ref[:colon]
	}
	return ref
}

func exactOCIRef(ref, digest string) string {
	return strings.TrimPrefix(ociRepository(ref), "oci://") + "@" + digest
}

func (s *Service) admit(ctx context.Context, item *types.CatalogItem, version string, resolved *resourcetargets.ResolvedTarget) (*catalog.AdmittedVersion, error) {
	if item.SourceID == "" {
		row, err := s.catalog.GetVersion(ctx, item.ID, version)
		if err != nil {
			return nil, err
		}
		return &catalog.AdmittedVersion{Version: row}, nil
	}
	return s.catalog.AdmitVersion(ctx, item.ID, version, environmentFor(resolved))
}

func (s *Service) resolveChartAdmission(ctx context.Context, orgID string, source Source) (string, string, error) {
	if source.AdmissionItemID != "" {
		version := source.AdmissionVersion
		if version == "" {
			version = source.Version
		}
		return source.AdmissionItemID, version, nil
	}
	items, _, err := s.catalog.ListVisible(ctx, orgID, types.CatalogListOptions{SourceID: source.SourceID})
	if err != nil {
		return "", "", err
	}
	var itemID, version string
	for _, item := range items {
		for _, candidate := range item.Versions {
			if candidate.ChartDigest != source.Digest || ociRepository(candidate.ChartRef) != ociRepository(source.Ref) {
				continue
			}
			if itemID != "" && (itemID != item.ID || version != candidate.Version) {
				return "", "", errors.New("chart_admission_identity_ambiguous")
			}
			itemID, version = item.ID, candidate.Version
		}
	}
	if itemID == "" {
		return "", "", errors.New("chart_admission_identity_not_found")
	}
	return itemID, version, nil
}

func (s *Service) chartMetadata(ctx context.Context, ref, digest, expectedVersion string) ([]byte, error) {
	if s.charts == nil {
		return nil, errors.New("chart metadata fetcher is not configured")
	}
	artifact, err := s.charts.Fetch(ctx, exactOCIRef(ref, digest))
	if err != nil {
		return nil, err
	}
	if artifact == nil || artifact.Digest != digest {
		return nil, errors.New("chart digest mismatch")
	}
	if chartRaw := artifact.Files["Chart.yaml"]; len(chartRaw) > 0 {
		var chart struct {
			Version string `yaml:"version"`
		}
		if err := yaml.Unmarshal(chartRaw, &chart); err != nil || chart.Version != expectedVersion {
			return nil, errors.New("chart version does not match signed admission identity")
		}
	}
	return artifact.Files["inari/observability.yaml"], nil
}

func (s *Service) normalizeSource(ctx context.Context, req PlanRequest, orgID string, resolved *resourcetargets.ResolvedTarget) (*normalizedSource, error) {
	if req.Source == nil {
		return nil, errors.New("deployment source is required")
	}
	source := *req.Source
	if s.catalog == nil {
		return nil, errors.New("catalog is not configured")
	}
	if source.Kind == SourceChart {
		if source.SourceID == "" || source.Ref == "" || source.Version == "" || source.Digest == "" || strings.HasSuffix(source.Ref, ":latest") {
			return nil, errors.New("direct chart requires trusted source, OCI repository, exact version, and digest")
		}
		itemID, admissionVersion, err := s.resolveChartAdmission(ctx, orgID, source)
		if err != nil {
			return nil, err
		}
		item, err := s.catalog.GetItemByID(ctx, itemID)
		if err != nil {
			return nil, err
		}
		if resolved != nil && resolved.Cluster != nil {
			if err := s.catalog.EnsureVisible(ctx, orgID, resolved.Cluster.ID, itemID); err != nil {
				return nil, err
			}
		}
		admitted, err := s.admit(ctx, item, admissionVersion, resolved)
		if err != nil {
			return nil, err
		}
		version := admitted.Version
		if version.ChartDigest != source.Digest || ociRepository(version.ChartRef) != ociRepository(source.Ref) || version.Version != source.Version {
			return nil, errors.New("direct chart pin does not match signed index identity")
		}
		metadata, err := s.chartMetadata(ctx, source.Ref, source.Digest, source.Version)
		if err != nil {
			return nil, err
		}
		capability, capabilityDigest, err := CapabilityFromCatalogPayload(version.Payload, metadata)
		if err != nil {
			return nil, err
		}
		return &normalizedSource{source: source, app: ArtifactPin{ItemID: itemID, Version: source.Version, PackageVersion: version.PackageVersion, Ref: source.Ref, Digest: source.Digest, SourceID: item.SourceID, ChartRef: source.Ref, ChartDigest: source.Digest}, capability: capability, capabilityDigest: capabilityDigest, managedChart: true, item: item, version: version}, nil
	}
	if source.Kind != SourceCatalog && source.Kind != SourceTemplate {
		return nil, errors.New("source kind must be catalog, chart, or template")
	}
	if source.ItemID == "" {
		return nil, errors.New("source itemId is required")
	}
	item, err := s.catalog.GetItemByID(ctx, source.ItemID)
	if err != nil {
		return nil, err
	}
	version := source.Version
	if version == "" {
		version, err = s.catalog.EffectiveVersion(ctx, orgID, source.ItemID, "stable")
		if err != nil {
			return nil, err
		}
		source.Version = version
	}
	if resolved != nil && resolved.Cluster != nil {
		if err := s.catalog.EnsureVisible(ctx, orgID, resolved.Cluster.ID, source.ItemID); err != nil {
			return nil, err
		}
	}
	admitted, err := s.admit(ctx, item, version, resolved)
	if err != nil {
		return nil, err
	}
	row := admitted.Version
	if source.Digest != "" && source.Digest != row.ArtifactDigest {
		return nil, errors.New("application digest mismatch")
	}
	app := ArtifactPin{ItemID: item.ID, Version: row.Version, PackageVersion: row.PackageVersion, Ref: row.ArtifactRef, Digest: row.ArtifactDigest, SourceID: item.SourceID, ChartRef: row.ChartRef, ChartDigest: row.ChartDigest}
	var chartMetadata []byte
	if row.ChartRef != "" {
		chartMetadata, err = s.chartMetadata(ctx, row.ChartRef, row.ChartDigest, row.Version)
		if err != nil {
			return nil, err
		}
	}
	var capability *observability.Capability
	var capabilityDigest string
	if source.Kind == SourceTemplate {
		capability, capabilityDigest, err = CapabilityFromTemplatePayload(row.Payload)
	} else {
		capability, capabilityDigest, err = CapabilityFromCatalogPayload(row.Payload, chartMetadata)
	}
	if err != nil {
		return nil, err
	}
	return &normalizedSource{source: source, app: app, capability: capability, capabilityDigest: capabilityDigest, managedChart: row.ChartRef != "", item: item, version: row}, nil
}

func packRGD(version *types.CatalogItemVersion) []byte {
	var payload struct {
		RGD string `json:"rgd"`
	}
	if err := json.Unmarshal(version.Payload, &payload); err != nil {
		return nil
	}
	return []byte(payload.RGD)
}

func packType(version *types.CatalogItemVersion) string {
	var payload struct {
		Admission struct {
			Type string `json:"type"`
		} `json:"admission"`
	}
	if err := json.Unmarshal(version.Payload, &payload); err != nil {
		return ""
	}
	return payload.Admission.Type
}

func (s *Service) compatiblePacks(ctx context.Context, normalized *normalizedSource) ([]PackPin, error) {
	if normalized.capability == nil {
		return []PackPin{}, nil
	}
	itemID := normalized.item.SourceID + "/" + normalized.capability.ObservabilityPack.Package
	item, err := s.catalog.GetItemByID(ctx, itemID)
	if err != nil {
		return nil, err
	}
	if item.Category != "observability" {
		return nil, errors.New("selected companion is not an observability pack")
	}
	versions, err := s.catalog.ListVersions(ctx, itemID)
	if err != nil {
		return nil, err
	}
	out := []PackPin{}
	for _, version := range versions {
		pin := PackPin{ArtifactPin: ArtifactPin{ItemID: itemID, Version: version.Version, PackageVersion: version.PackageVersion, Ref: version.ArtifactRef, Digest: version.ArtifactDigest, SourceID: item.SourceID}, RenderContract: observability.PackRenderContractV2}
		if packType(&version) != "kro-rgd" {
			continue
		}
		if err := ValidatePackRGD(packRGD(&version), pin, normalized.capability); err != nil {
			continue
		}
		out = append(out, pin)
	}
	return out, nil
}
