package catalog

import (
	"context"
	"testing"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/artifactadmission"
	"github.com/7K-Inari/inari-server/internal/oci"
)

const (
	smokeSHA       = "0123456789abcdef0123456789abcdef01234567"
	smokeSourceSHA = "abcdef0123456789abcdef0123456789abcdef01"
	smokeDigest    = "sha256:52ccaee6d4dd272e54bfccda77738b42e1edf0e4a20c27e23f0b6c15d01aef79"
)

type smokeBackend struct {
	descriptor artifactadmission.ArtifactDescriptor
	expected   *artifactadmission.PublisherExpectation
}

func (b *smokeBackend) Fetch(context.Context, string) (*oci.Artifact, error) {
	return &oci.Artifact{Digest: b.descriptor.Digest, MediaType: b.descriptor.MediaType, Files: map[string][]byte{"suite.yaml": []byte("suiteSchema: inari.smoke.v1\n")}}, nil
}
func (b *smokeBackend) VerifySignature(_ context.Context, _ string, expected artifactadmission.PublisherExpectation) error {
	b.expected = &expected
	return nil
}
func (*smokeBackend) VerifyAttestations(context.Context, string, artifactadmission.PublisherExpectation, string) ([]artifactadmission.Attestation, error) {
	return nil, nil
}

func smokeSource() trustedsource.Source {
	return trustedsource.Source{
		ID: "hiroba", IndexRef: "ghcr.io/7k-hiroba/example/catalog/index:latest", TrustTier: trustedsource.TrustExperimental,
		ArtifactPrefixes: []string{"ghcr.io/7k-hiroba/example/"},
		Publisher: trustedsource.Publisher{
			Issuer: "https://token.actions.githubusercontent.com", Repository: "7K-Hiroba/workflows", Workflows: trustedsource.DefaultArtifactWorkflows(), WorkflowSHA: smokeSHA,
			SourceRepository: "7K-Hiroba/example", SourceWorkflow: ".github/workflows/release.yml",
		},
	}
}

func smokeDescriptor() artifactadmission.ArtifactDescriptor {
	return artifactadmission.ArtifactDescriptor{
		Ref: "ghcr.io/7k-hiroba/example/smoke/web:1.0.0", Digest: smokeDigest,
		MediaType: trustedsource.SmokeSuiteMediaType, SourceSHA: smokeSourceSHA,
		ReleaseTag: "web-v1.0.0", PackageVersion: "1.0.0", Component: "web",
		Producer: trustedsource.Producer{WorkflowPath: ".github/workflows/release-smoke-suite.yml", WorkflowSHA: smokeSHA, RunID: "123", RunAttempt: 1, RunURI: "https://github.com/7K-Hiroba/example/actions/runs/123"},
	}
}

func TestAdmitSmokeSuiteUsesConfiguredSourceIdentity(t *testing.T) {
	source := smokeSource()
	descriptor := smokeDescriptor()
	descriptor.App = "caller-claim"
	backend := &smokeBackend{descriptor: descriptor}
	service := NewServiceWithSources(nil, NewStore(), nil, nil, []SourceSync{{Kind: "catalog", Source: source}}).WithAdmissionVerifier(artifactadmission.NewVerifier(backend))
	admitted, err := service.AdmitSmokeSuite(context.Background(), source.ID, descriptor, trustedsource.EnvironmentDevelopment)
	if err != nil {
		t.Fatalf("AdmitSmokeSuite: %v", err)
	}
	if admitted == nil || admitted.Evidence == nil || admitted.Evidence.Files["suite.yaml"] == nil {
		t.Fatalf("admitted suite is incomplete: %#v", admitted)
	}
	if admitted.Descriptor.App != "example" || backend.expected == nil || backend.expected.Role != trustedsource.ArtifactSmokeSuite || backend.expected.SourceSHA != smokeSourceSHA {
		t.Fatalf("source identity was not server-derived: %#v, expectation %#v", admitted.Descriptor, backend.expected)
	}
	if admitted.SourceFingerprint == "" {
		t.Fatal("source fingerprint is empty")
	}
}

func TestAdmitSmokeSuiteRejectsUnknownSource(t *testing.T) {
	service := NewServiceWithSources(nil, NewStore(), nil, nil, nil).WithAdmissionVerifier(artifactadmission.NewVerifier(&smokeBackend{descriptor: smokeDescriptor()}))
	if _, err := service.AdmitSmokeSuite(context.Background(), "unknown", smokeDescriptor(), trustedsource.EnvironmentDevelopment); !artifactadmission.IsCode(err, artifactadmission.CodeInvalidRequest) {
		t.Fatalf("error = %v, want invalid_admission_request", err)
	}
}
