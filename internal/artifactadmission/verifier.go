package artifactadmission

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/oci"
)

// Backend is the registry and sigstore boundary. Production uses cosign and
// OCI; tests use hermetic fakes with verified evidence fixtures.
type Backend interface {
	Fetch(ctx context.Context, ref string) (*oci.Artifact, error)
	VerifySignature(ctx context.Context, ref string, expected PublisherExpectation) error
	VerifyAttestations(ctx context.Context, ref string, expected PublisherExpectation, predicateType string) ([]Attestation, error)
}

type Verifier struct {
	backend Backend
}

func NewVerifier(backend Backend) *Verifier {
	return &Verifier{backend: backend}
}

var admissionDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (v *Verifier) VerifyIndex(ctx context.Context, source Source, artifact ArtifactDescriptor) error {
	_, err := v.admit(ctx, Request{Source: source, Role: trustedsource.ArtifactIndex, Artifact: artifact, TargetEnvironment: trustedsource.EnvironmentDevelopment, SyncOnly: true})
	return err
}

func (v *Verifier) AdmitArtifact(ctx context.Context, req Request) (*EvidenceSummary, error) {
	return v.admit(ctx, req)
}

func (v *Verifier) admit(ctx context.Context, req Request) (*EvidenceSummary, error) {
	if v.backend == nil {
		return nil, &Error{Code: CodeUnavailable, Err: errors.New("admission backend is not configured"), Temporary: true}
	}
	if req.Now.IsZero() {
		req.Now = time.Now()
	}
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	ref := immutableRef(req.Artifact.Ref, req.Artifact.Digest)
	unsigned := req.Source.AllowUnsigned != ""
	if unsigned && req.TargetEnvironment != trustedsource.EnvironmentDevelopment {
		return nil, &Error{Code: CodeUnsignedProduction, Ref: ref, Err: errors.New("unsigned artifacts are restricted to an explicitly development target")}
	}
	artifact, err := v.backend.Fetch(ctx, ref)
	if err != nil {
		return nil, &Error{Code: CodeUnavailable, Ref: ref, Err: err, Temporary: true}
	}
	if artifact == nil || artifact.Digest != req.Artifact.Digest {
		return nil, &Error{Code: CodeDigestMismatch, Ref: ref, Err: fmt.Errorf("resolved digest does not match the signed index pin")}
	}
	if !matchesMediaType(artifact, req.Artifact.MediaType) {
		return nil, &Error{Code: CodeMediaTypeMismatch, Ref: ref, Err: fmt.Errorf("artifact media layout does not match %q", req.Artifact.MediaType)}
	}
	if unsigned {
		return &EvidenceSummary{Unsigned: true, ArtifactDigest: req.Artifact.Digest}, nil
	}
	expect := PublisherExpectation{Source: req.Source, Role: req.Role, SourceSHA: req.Artifact.SourceSHA, Producer: req.Artifact.Producer}
	if err := v.backend.VerifySignature(ctx, ref, expect); err != nil {
		return nil, admissionBackendError(CodeSignatureInvalid, ref, err)
	}
	summary := &EvidenceSummary{
		PublisherRepository: req.Source.Publisher.Repository,
		PublisherWorkflow:   expect.Workflow(), ArtifactDigest: req.Artifact.Digest,
	}
	if req.SyncOnly {
		return summary, nil
	}
	if req.Source.TrustTier != trustedsource.TrustOfficial && req.Source.TrustTier != trustedsource.TrustReviewed {
		return summary, nil
	}
	if req.Role == trustedsource.ArtifactIndex {
		return summary, nil
	}
	if err := v.verifyProvenance(ctx, ref, req, expect); err != nil {
		return nil, err
	}
	summary.ProvenanceDigest = req.Artifact.Digest
	evidenceDigest, err := v.verifyTestEvidence(ctx, ref, req, expect)
	if err != nil {
		return nil, err
	}
	summary.TestEvidenceDigest = evidenceDigest
	return summary, nil
}

func matchesMediaType(artifact *oci.Artifact, expected string) bool {
	if artifact == nil {
		return false
	}
	if expected != trustedsource.HelmChartMediaType {
		return artifact.MediaType == expected
	}
	if artifact.ConfigMediaType != "application/vnd.cncf.helm.config.v1+json" {
		return false
	}
	for _, mediaType := range artifact.LayerMediaTypes {
		if mediaType == expected {
			return true
		}
	}
	return false
}

func validateRequest(req Request) error {
	if !admissionDigestPattern.MatchString(req.Artifact.Digest) {
		return &Error{Code: CodeInvalidRequest, Ref: req.Artifact.Ref, Err: errors.New("an immutable sha256 artifact digest is required")}
	}
	if req.Artifact.Ref == "" || req.Artifact.MediaType == "" || req.Artifact.SourceSHA == "" {
		return &Error{Code: CodeInvalidRequest, Ref: req.Artifact.Ref, Err: errors.New("artifact ref, media type, and source SHA are required")}
	}
	if req.Source.AllowUnsigned != "" {
		if req.Source.TrustTier != trustedsource.TrustExperimental || req.Source.AllowUnsigned != trustedsource.AllowUnsignedDevelopmentOnly {
			return &Error{Code: CodeInvalidRequest, Ref: req.Artifact.Ref, Err: errors.New("allowUnsigned is valid only as development-only for experimental sources")}
		}
	}
	if req.Source.TrustTier != trustedsource.TrustOfficial && req.Source.TrustTier != trustedsource.TrustReviewed && req.Source.TrustTier != trustedsource.TrustExperimental {
		return &Error{Code: CodeInvalidRequest, Ref: req.Artifact.Ref, Err: errors.New("unknown trust tier")}
	}
	if req.Role == "" {
		return &Error{Code: CodeInvalidRequest, Ref: req.Artifact.Ref, Err: errors.New("artifact role is required")}
	}
	if req.Source.AllowUnsigned == "" && req.Source.Publisher.Workflows.For(req.Role) == "" {
		return &Error{Code: CodeInvalidRequest, Ref: req.Artifact.Ref, Err: errors.New("no publisher workflow is configured for the artifact role")}
	}
	repository := repositoryFor(req.Artifact.Ref)
	allowed := strings.HasPrefix(req.Artifact.Ref, "fixture://")
	for _, prefix := range req.Source.ArtifactPrefixes {
		if strings.HasPrefix(repository+"/", prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return &Error{Code: CodeNamespaceDenied, Ref: req.Artifact.Ref, Err: errors.New("artifact repository is outside the source allowlist")}
	}
	return nil
}

func admissionBackendError(code, ref string, err error) error {
	var admissionErr *Error
	if errors.As(err, &admissionErr) {
		return err
	}
	return &Error{Code: code, Ref: ref, Err: err, Temporary: code == CodeUnavailable}
}

// Source aliases the API contract type to keep call sites readable.
type Source = trustedsource.Source
