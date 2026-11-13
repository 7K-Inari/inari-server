package artifactadmission

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/oci"
)

const (
	testSHA       = "0123456789abcdef0123456789abcdef01234567"
	testSourceSHA = "abcdef0123456789abcdef0123456789abcdef01"
	testDigest    = "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79"
)

type fakeBackend struct {
	request        Request
	artifact       *oci.Artifact
	fetchErr       error
	signatureErr   error
	attestErr      error
	expect         []PublisherExpectation
	attestCalls    int
	slsaMutate     func(*trustedsource.Statement)
	evidenceMutate func(*trustedsource.TestEvidence)
	omit           map[string]bool
}

func (f *fakeBackend) Fetch(context.Context, string) (*oci.Artifact, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.artifact, nil
}

func (f *fakeBackend) VerifySignature(_ context.Context, _ string, expected PublisherExpectation) error {
	f.expect = append(f.expect, expected)
	return f.signatureErr
}

func (f *fakeBackend) VerifyAttestations(_ context.Context, _ string, expected PublisherExpectation, predicateType string) ([]Attestation, error) {
	f.attestCalls++
	if f.attestErr != nil {
		return nil, f.attestErr
	}
	if f.omit[predicateType] {
		return nil, nil
	}
	if predicateType == trustedsource.SLSAProvenancePredicateType {
		statement := validSLSA(expected, f.request.Artifact)
		if f.slsaMutate != nil {
			f.slsaMutate(statement)
		}
		raw, _ := json.Marshal(statement)
		return []Attestation{{PredicateType: predicateType, Payload: raw}}, nil
	}
	evidence := validEvidence(expected, f.request.Artifact)
	if f.evidenceMutate != nil {
		f.evidenceMutate(evidence)
	}
	raw, _ := json.Marshal(evidence)
	return []Attestation{{PredicateType: predicateType, Payload: raw}}, nil
}

func validRequest() Request {
	return Request{
		Source: Source{
			ID: "core", TrustTier: trustedsource.TrustOfficial,
			ArtifactPrefixes: []string{"ghcr.io/7k-hiroba/argocd/"},
			Publisher: trustedsource.Publisher{
				Issuer: "https://token.actions.githubusercontent.com", Repository: "7k-hiroba/workflows",
				Workflows: trustedsource.DefaultArtifactWorkflows(), WorkflowSHA: testSHA,
				SourceRepository: "7k-hiroba/argocd", SourceWorkflow: ".github/workflows/release.yml",
				SourceRef: "refs/heads/main", Event: "push", ReleaseEnvironment: "release",
			},
		},
		Role: trustedsource.ArtifactCatalogPackage,
		Artifact: ArtifactDescriptor{
			Ref: "ghcr.io/7k-hiroba/argocd/catalog/web-service:1.2.0", Digest: testDigest,
			MediaType: trustedsource.CatalogPackageMediaType, SourceSHA: testSourceSHA,
			ReleaseTag: "web-service-v1.2.0", PackageVersion: "1.2.0", App: "argocd", Component: "web-service",
			Producer: trustedsource.Producer{WorkflowPath: ".github/workflows/release-oci.yml", WorkflowSHA: testSHA, RunID: "123", RunAttempt: 1, RunURI: "https://github.com/7k-hiroba/argocd/actions/runs/123"},
			Lanes:    []trustedsource.Lane{{Name: "test-packages", Required: true, Status: "passed", RunID: "123", JobID: "456", SourceSHA: testSourceSHA}},
		},
		TargetEnvironment: trustedsource.EnvironmentProduction,
		Now:               time.Date(2026, 11, 13, 12, 30, 0, 0, time.UTC),
	}
}

func validSLSA(expected PublisherExpectation, artifact ArtifactDescriptor) *trustedsource.Statement {
	return &trustedsource.Statement{
		Type: "https://in-toto.io/Statement/v1", PredicateType: trustedsource.SLSAProvenancePredicateType,
		Subject: []trustedsource.Subject{{Name: repositoryFor(artifact.Ref), Digest: map[string]string{"sha256": strings.TrimPrefix(artifact.Digest, "sha256:")}}},
		Predicate: trustedsource.Provenance{
			BuildDefinition: trustedsource.BuildDefinition{
				BuildType: "https://actions.github.io/buildtypes/workflow/v1",
				ExternalParameters: trustedsource.ExternalParameters{
					Repository: expected.Source.Publisher.SourceRepository, SourceSHA: expected.SourceSHA,
					ReleaseTag: artifact.ReleaseTag, PackageVersion: artifact.PackageVersion,
					Event: expected.Source.Publisher.Event, SourceRef: expected.Source.Publisher.SourceRef,
					Environment: expected.Source.Publisher.ReleaseEnvironment, RunID: artifact.Producer.RunID, RunAttempt: artifact.Producer.RunAttempt,
				},
				ResolvedDependencies: []trustedsource.Dependency{{URI: "https://github.com/" + expected.Source.Publisher.Repository + "/" + expected.Workflow(), Digest: map[string]string{"sha": expected.Source.Publisher.WorkflowSHA}}},
			},
			RunDetails: trustedsource.RunDetails{Builder: trustedsource.Builder{ID: expected.WorkflowURI()}, Metadata: trustedsource.Metadata{InvocationID: artifact.Producer.RunURI}},
		},
	}
}

func validEvidence(expected PublisherExpectation, artifact ArtifactDescriptor) *trustedsource.TestEvidence {
	return &trustedsource.TestEvidence{
		Schema: trustedsource.TestEvidenceSchema, App: artifact.App, Component: artifact.Component,
		TrustTier: expected.Source.TrustTier, SourceRepository: expected.Source.Publisher.SourceRepository,
		SourceSHA: expected.SourceSHA, ReleaseTag: artifact.ReleaseTag,
		Artifact: trustedsource.ArtifactEvidence{Repository: repositoryFor(artifact.Ref), Digest: artifact.Digest, MediaType: artifact.MediaType},
		Producer: artifact.Producer, Lanes: artifact.Lanes, Compatibility: artifact.Compatibility, Runtime: artifact.Runtime,
		FinishedAt: "2026-11-13T12:00:00Z", EvidenceDigest: testDigest,
	}
}

func newTestBackend(req Request) *fakeBackend {
	return &fakeBackend{request: req, artifact: &oci.Artifact{Digest: req.Artifact.Digest, MediaType: req.Artifact.MediaType}, omit: map[string]bool{}}
}

func TestAdmitOfficialArtifact(t *testing.T) {
	req := validRequest()
	backend := newTestBackend(req)
	summary, err := NewVerifier(backend).AdmitArtifact(context.Background(), req)
	if err != nil {
		t.Fatalf("AdmitArtifact: %v", err)
	}
	if summary.Unsigned || summary.ArtifactDigest != testDigest || summary.ProvenanceDigest != testDigest || summary.TestEvidenceDigest != testDigest {
		t.Fatalf("summary = %+v", summary)
	}
	if backend.attestCalls != 2 {
		t.Fatalf("attestation calls = %d, want provenance and test evidence", backend.attestCalls)
	}
}

func TestVerifyIndexUsesIndexLaneWithoutDeployEvidence(t *testing.T) {
	req := validRequest()
	req.Role = trustedsource.ArtifactIndex
	req.Artifact.MediaType = trustedsource.CatalogIndexMediaType
	req.Artifact.Producer.WorkflowPath = ".github/workflows/release.yml"
	backend := newTestBackend(req)
	if err := NewVerifier(backend).VerifyIndex(context.Background(), req.Source, req.Artifact); err != nil {
		t.Fatalf("VerifyIndex: %v", err)
	}
	if len(backend.expect) != 1 || backend.expect[0].Role != trustedsource.ArtifactIndex {
		t.Fatalf("expectations = %+v", backend.expect)
	}
	if backend.attestCalls != 0 {
		t.Fatalf("sync unexpectedly required deploy evidence")
	}
}

func TestAdmissionRejectsDigestMediaAndSignatureFailures(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		mutate     func(*Request, *fakeBackend)
	}{
		{"digest", CodeDigestMismatch, func(r *Request, b *fakeBackend) { b.artifact.Digest = "sha256:" + strings.Repeat("0", 64) }},
		{"media", CodeMediaTypeMismatch, func(r *Request, b *fakeBackend) { b.artifact.MediaType = trustedsource.TemplateMediaType }},
		{"signature", CodeSignatureInvalid, func(r *Request, b *fakeBackend) { b.signatureErr = errors.New("bad signature") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			backend := newTestBackend(req)
			tc.mutate(&req, backend)
			_, err := NewVerifier(backend).AdmitArtifact(context.Background(), req)
			if !IsCode(err, tc.code) {
				t.Fatalf("error = %v, want %s", err, tc.code)
			}
		})
	}
}

func TestAdmissionRejectsBadProvenanceAndMissingTests(t *testing.T) {
	req := validRequest()
	backend := newTestBackend(req)
	backend.slsaMutate = func(s *trustedsource.Statement) {
		s.Predicate.RunDetails.Builder.ID = "https://github.com/untrusted/workflow@main"
	}
	if _, err := NewVerifier(backend).AdmitArtifact(context.Background(), req); !IsCode(err, CodeProvenanceInvalid) {
		t.Fatalf("error = %v, want provenance_invalid", err)
	}

	backend = newTestBackend(req)
	backend.omit[trustedsource.TestEvidencePredicateType] = true
	if _, err := NewVerifier(backend).AdmitArtifact(context.Background(), req); !IsCode(err, CodeTestEvidenceInvalid) {
		t.Fatalf("error = %v, want test_evidence_invalid", err)
	}
}

func TestAdmissionRejectsStaleReviewedCompatibility(t *testing.T) {
	req := validRequest()
	req.Source.TrustTier = trustedsource.TrustReviewed
	req.RequireUICompatibility = true
	req.Artifact.Compatibility = &trustedsource.Compatibility{
		Matrix: map[string]string{"stable": "passed", "previous-stable": "passed"}, Result: "passed",
		CompletedAt: "2026-11-01T12:00:00Z", Browser: "passed", Slots: []string{"cluster-tab"},
	}
	backend := newTestBackend(req)
	if _, err := NewVerifier(backend).AdmitArtifact(context.Background(), req); !IsCode(err, CodeTestEvidenceInvalid) {
		t.Fatalf("error = %v, want test_evidence_invalid", err)
	}
}

func TestUnsignedDevelopmentOnly(t *testing.T) {
	for _, environment := range []trustedsource.Environment{trustedsource.EnvironmentDevelopment} {
		req := validRequest()
		req.Source.TrustTier = trustedsource.TrustExperimental
		req.Source.AllowUnsigned = trustedsource.AllowUnsignedDevelopmentOnly
		req.TargetEnvironment = environment
		backend := newTestBackend(req)
		summary, err := NewVerifier(backend).AdmitArtifact(context.Background(), req)
		if err != nil || !summary.Unsigned {
			t.Fatalf("environment %s: summary=%+v err=%v", environment, summary, err)
		}
		if backend.attestCalls != 0 || len(backend.expect) != 0 {
			t.Fatalf("unsigned path invoked signature/evidence backend")
		}
	}
	for _, environment := range []trustedsource.Environment{"", trustedsource.EnvironmentStaging, trustedsource.EnvironmentProduction} {
		req := validRequest()
		req.Source.TrustTier = trustedsource.TrustExperimental
		req.Source.AllowUnsigned = trustedsource.AllowUnsignedDevelopmentOnly
		req.TargetEnvironment = environment
		backend := newTestBackend(req)
		if _, err := NewVerifier(backend).AdmitArtifact(context.Background(), req); !IsCode(err, CodeUnsignedProduction) {
			t.Fatalf("environment %q: error = %v, want production denial", environment, err)
		}
	}
}

func TestExperimentalSignedNeedsNoPredicates(t *testing.T) {
	req := validRequest()
	req.Source.TrustTier = trustedsource.TrustExperimental
	backend := newTestBackend(req)
	backend.omit[trustedsource.SLSAProvenancePredicateType] = true
	backend.omit[trustedsource.TestEvidencePredicateType] = true
	if _, err := NewVerifier(backend).AdmitArtifact(context.Background(), req); err != nil {
		t.Fatalf("signed experimental rejected: %v", err)
	}
}

func TestSyncOnlySkipsDeployEvidenceAndRejectsForeignNamespace(t *testing.T) {
	req := validRequest()
	req.SyncOnly = true
	backend := newTestBackend(req)
	backend.omit[trustedsource.SLSAProvenancePredicateType] = true
	backend.omit[trustedsource.TestEvidencePredicateType] = true
	if _, err := NewVerifier(backend).AdmitArtifact(context.Background(), req); err != nil {
		t.Fatalf("sync-only verification required deploy evidence: %v", err)
	}

	req.Artifact.Ref = "ghcr.io/untrusted/web-service:1.2.0"
	if _, err := NewVerifier(backend).AdmitArtifact(context.Background(), req); !IsCode(err, CodeNamespaceDenied) {
		t.Fatalf("error = %v, want artifact_namespace_denied", err)
	}
}

func TestHelmMediaTypeUsesManifestConfigAndLayer(t *testing.T) {
	req := validRequest()
	req.Role = trustedsource.ArtifactHelmChart
	req.Artifact.MediaType = trustedsource.HelmChartMediaType
	req.Artifact.Producer.WorkflowPath = ".github/workflows/release-chart.yml"
	backend := newTestBackend(req)
	backend.artifact.MediaType = "application/vnd.oci.image.manifest.v1+json"
	backend.artifact.ConfigMediaType = "application/vnd.cncf.helm.config.v1+json"
	backend.artifact.LayerMediaTypes = []string{trustedsource.HelmChartMediaType}
	if _, err := NewVerifier(backend).AdmitArtifact(context.Background(), req); err != nil {
		t.Fatalf("valid OCI Helm media layout rejected: %v", err)
	}
}

func TestUnavailableIsTemporary(t *testing.T) {
	req := validRequest()
	backend := newTestBackend(req)
	backend.fetchErr = errors.New("registry unavailable")
	_, err := NewVerifier(backend).AdmitArtifact(context.Background(), req)
	if !IsCode(err, CodeUnavailable) || !IsTemporary(err) {
		t.Fatalf("error = %v, want temporary unavailable", err)
	}
}
