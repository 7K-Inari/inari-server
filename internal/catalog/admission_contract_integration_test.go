//go:build integration

package catalog_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/oci"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

type contractEvidenceBackend struct {
	slsa      []byte
	evidence  []byte
	mediaType string
	digest    string
}

func (b *contractEvidenceBackend) Fetch(context.Context, string) (*oci.Artifact, error) {
	return &oci.Artifact{Digest: b.digest, MediaType: b.mediaType}, nil
}

func (b *contractEvidenceBackend) VerifySignature(context.Context, string, artifactadmission.PublisherExpectation) error {
	return nil
}

func (b *contractEvidenceBackend) VerifyAttestations(_ context.Context, _ string, _ artifactadmission.PublisherExpectation, predicateType string) ([]artifactadmission.Attestation, error) {
	if predicateType == trustedsource.SLSAProvenancePredicateType {
		return []artifactadmission.Attestation{{PredicateType: predicateType, Payload: b.slsa}}, nil
	}
	return []artifactadmission.Attestation{{PredicateType: predicateType, Payload: b.evidence}}, nil
}

func TestAdmitVersionWithSharedContractFixtures(t *testing.T) {
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sourceFile, err := trustedsource.DecodeFile(read("source-file.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	index, err := trustedsource.DecodeIndex(read("catalog-index.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := sourceFile.Catalog.Sources[0]
	entry := index.Packages[0]
	fingerprint, err := sourceFile.Fingerprint(source)
	if err != nil {
		t.Fatal(err)
	}
	item := &types.CatalogItem{
		ID: "community/web-service", Source: types.CatalogSourceCurated, SourceID: source.ID,
		TrustTier: string(source.TrustTier), Name: entry.Name, DisplayName: entry.Name,
		SourceFingerprint: fingerprint, SourceGeneration: 1, SnapshotPresent: true,
	}
	version := &types.CatalogItemVersion{
		ItemID: item.ID, Version: entry.Version, PackageVersion: entry.PackageVersion, Channel: entry.Channel,
		ArtifactRef: entry.OCIRef, ArtifactDigest: entry.Digest, SnapshotPresent: true,
		Payload: []byte(`{"admission":` + string(mustJSON(t, entry)) + `}`),
	}
	service := catalog.NewServiceWithSources(database, catalog.NewStore(), nil, audit.NewStore(), []catalog.SourceSync{{Kind: "catalog", Source: source}})
	if err := service.UpsertItem(ctx, item, version); err != nil {
		t.Fatal(err)
	}
	backend := &contractEvidenceBackend{slsa: read("slsa-provenance.json"), evidence: read("test-evidence.json"), mediaType: entry.MediaType, digest: entry.Digest}
	service.WithAdmissionVerifier(artifactadmission.NewVerifier(backend))
	if _, err := service.AdmitVersion(ctx, item.ID, entry.Version, trustedsource.EnvironmentProduction); err != nil {
		t.Fatalf("shared contract fixtures must admit: %v", err)
	}
}

func TestAdmitVersionRequiresFreshUICompatibility(t *testing.T) {
	for _, tc := range []struct {
		name          string
		compatibility *trustedsource.Compatibility
		wantError     bool
	}{
		{"missing", nil, true},
		{"stale", &trustedsource.Compatibility{Matrix: map[string]string{"stable": "passed", "previous-stable": "passed"}, Result: "passed", CompletedAt: "2026-11-01T12:00:00Z", Browser: "passed", Slots: []string{"cluster-tab:health"}}, true},
		{"valid", &trustedsource.Compatibility{Matrix: map[string]string{"stable": "passed", "previous-stable": "passed"}, Result: "passed", CompletedAt: time.Now().UTC().Format(time.RFC3339), Browser: "passed", Slots: []string{"cluster-tab:health"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pg, err := testutil.SharedPostgres(ctx)
			if err != nil {
				t.Skipf("testcontainers unavailable: %v", err)
			}
			database, err := testdb.NewDatabase(t, pg)
			if err != nil {
				t.Fatal(err)
			}
			read := func(name string) []byte {
				t.Helper()
				raw, err := os.ReadFile("testdata/" + name)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			sourceFile, err := trustedsource.DecodeFile(read("source-file.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			index, err := trustedsource.DecodeIndex(read("catalog-index.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			source := sourceFile.Catalog.Sources[0]
			entry := index.Packages[0]
			entry.Lanes = append(entry.Lanes, trustedsource.Lane{Name: "ui", Required: true, Status: "passed", RunID: "123", JobID: "456", SourceSHA: entry.SourceSHA})
			entry.Compatibility = tc.compatibility
			fingerprint, err := sourceFile.Fingerprint(source)
			if err != nil {
				t.Fatal(err)
			}
			item := &types.CatalogItem{
				ID: "community/web-service", Source: types.CatalogSourceCurated, SourceID: source.ID,
				TrustTier: string(source.TrustTier), Name: entry.Name, DisplayName: entry.Name,
				SourceFingerprint: fingerprint, SourceGeneration: 1, SnapshotPresent: true,
			}
			version := &types.CatalogItemVersion{
				ItemID: item.ID, Version: entry.Version, PackageVersion: entry.PackageVersion, Channel: entry.Channel,
				ArtifactRef: entry.OCIRef, ArtifactDigest: entry.Digest, SnapshotPresent: true,
				Payload: []byte(`{"admission":` + string(mustJSON(t, entry)) + `}`),
			}
			service := catalog.NewServiceWithSources(database, catalog.NewStore(), nil, audit.NewStore(), []catalog.SourceSync{{Kind: "catalog", Source: source}})
			if err := service.UpsertItem(ctx, item, version); err != nil {
				t.Fatal(err)
			}
			var evidence trustedsource.TestEvidence
			if err := json.Unmarshal(read("test-evidence.json"), &evidence); err != nil {
				t.Fatal(err)
			}
			evidence.Compatibility = tc.compatibility
			backend := &contractEvidenceBackend{slsa: read("slsa-provenance.json"), evidence: mustJSON(t, evidence), mediaType: entry.MediaType, digest: entry.Digest}
			service.WithAdmissionVerifier(artifactadmission.NewVerifier(backend))
			_, err = service.AdmitVersion(ctx, item.ID, entry.Version, trustedsource.EnvironmentProduction)
			if tc.wantError && !artifactadmission.IsCode(err, artifactadmission.CodeTestEvidenceInvalid) {
				t.Fatalf("error = %v, want test_evidence_invalid", err)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("valid UI evidence rejected: %v", err)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
