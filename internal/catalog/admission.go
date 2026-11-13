package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/oci"
	"github.com/7K-Inari/inari-server/internal/types"
)

type AdmittedVersion struct {
	Version         *types.CatalogItemVersion
	PackageEvidence *artifactadmission.EvidenceSummary
	ChartEvidence   *artifactadmission.EvidenceSummary
}

// WithAdmissionVerifier enables deploy/render admission on the catalog facade.
func (s *Service) WithAdmissionVerifier(verifier *artifactadmission.Verifier) *Service {
	s.admission = verifier
	return s
}

// AdmitVersion resolves an active source-qualified version and verifies its
// package (and optional chart) again against the current source policy and
// immutable stored digest. It never follows latest or a channel ref.
func (s *Service) AdmitVersion(ctx context.Context, itemID, version string, environment trustedsource.Environment) (*AdmittedVersion, error) {
	if s.admission == nil {
		return nil, &artifactadmission.Error{Code: artifactadmission.CodeUnavailable, Err: errors.New("deploy admission is not configured"), Temporary: true}
	}
	item, err := s.store.GetItem(ctx, s.db.Pool, itemID)
	if err != nil {
		return nil, err
	}
	if !item.SnapshotPresent {
		return nil, ErrItemNotFound
	}
	ver, err := s.GetVersion(ctx, itemID, version)
	if err != nil {
		return nil, err
	}
	source, found := s.policies[item.SourceID]
	if !found {
		return nil, &artifactadmission.Error{Code: artifactadmission.CodeInvalidRequest, Ref: itemID, Err: errors.New("source is not configured")}
	}
	fingerprint, err := (&trustedsource.File{}).Fingerprint(source)
	if err != nil {
		return nil, err
	}
	if item.SourceFingerprint != "" && item.SourceFingerprint != fingerprint {
		return nil, &artifactadmission.Error{Code: artifactadmission.CodeInvalidRequest, Ref: itemID, Err: errors.New("source policy changed; a fresh verified sync is required")}
	}
	entry, err := admissionEntry(ver.Payload)
	if err != nil {
		return nil, err
	}
	role := trustedsource.ArtifactCatalogPackage
	if item.Source == types.CatalogSourceTemplate {
		role = trustedsource.ArtifactTemplate
	}
	descriptor := artifactadmission.ArtifactDescriptor{
		Ref: ver.ArtifactRef, Digest: ver.ArtifactDigest, MediaType: entry.MediaType,
		SourceSHA: entry.SourceSHA, ReleaseTag: entry.ReleaseTag,
		PackageVersion: ver.PackageVersion, App: item.SourceID, Component: item.Name,
		Producer: entry.Producer, Lanes: entry.Lanes, Compatibility: entry.Compatibility, Runtime: entry.Runtime,
	}
	if descriptor.PackageVersion == "" {
		descriptor.PackageVersion = ver.Version
	}
	packageEvidence, err := s.admission.AdmitArtifact(ctx, artifactadmission.Request{
		Source: source, Role: role, Artifact: descriptor, TargetEnvironment: environment, Now: s.now(),
	})
	if err != nil {
		return nil, err
	}
	out := &AdmittedVersion{Version: ver, PackageEvidence: packageEvidence}
	if ver.ChartRef != "" {
		if entry.ChartProducer == nil {
			return nil, &artifactadmission.Error{Code: artifactadmission.CodeInvalidRequest, Ref: itemID, Err: errors.New("chart release producer is missing")}
		}
		chartDescriptor := descriptor
		chartDescriptor.Ref = ver.ChartRef
		chartDescriptor.Digest = ver.ChartDigest
		chartDescriptor.MediaType = trustedsource.HelmChartMediaType
		chartDescriptor.Producer = *entry.ChartProducer
		chartEvidence, err := s.admission.AdmitArtifact(ctx, artifactadmission.Request{
			Source: source, Role: trustedsource.ArtifactHelmChart, Artifact: chartDescriptor, TargetEnvironment: environment, Now: s.now(),
		})
		if err != nil {
			return nil, err
		}
		out.ChartEvidence = chartEvidence
	}
	return out, nil
}

// fixtureBackend is used only by NewService's local FixturePuller path. It
// keeps existing internal integration fixtures independent of a live registry;
// production sources are constructed through NewServiceWithSources.
type fixtureBackend struct{}

func (fixtureBackend) Fetch(_ context.Context, ref string) (*oci.Artifact, error) {
	digest := ref
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		digest = ref[at+1:]
	}
	return &oci.Artifact{Digest: digest, MediaType: trustedsource.CatalogPackageMediaType}, nil
}

func (fixtureBackend) VerifySignature(context.Context, string, artifactadmission.PublisherExpectation) error {
	return nil
}

func (fixtureBackend) VerifyAttestations(context.Context, string, artifactadmission.PublisherExpectation, string) ([]artifactadmission.Attestation, error) {
	return nil, nil
}

func admissionEntry(payload json.RawMessage) (trustedsource.IndexEntry, error) {
	var entry trustedsource.IndexEntry
	var body struct {
		Admission trustedsource.IndexEntry `json:"admission"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return entry, err
	}
	return body.Admission, nil
}
