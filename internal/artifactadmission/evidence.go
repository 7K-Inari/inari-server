package artifactadmission

import (
	"context"
	"errors"
	"fmt"
	"strings"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
)

func (v *Verifier) verifyProvenance(ctx context.Context, ref string, req Request, expected PublisherExpectation) error {
	attestations, err := v.backend.VerifyAttestations(ctx, ref, expected, trustedsource.SLSAProvenancePredicateType)
	if err != nil {
		return admissionBackendError(CodeUnavailable, ref, err)
	}
	if len(attestations) == 0 {
		return &Error{Code: CodeProvenanceInvalid, Ref: ref, Err: errors.New("missing registry-referrer SLSA provenance")}
	}
	for _, attestation := range attestations {
		if attestation.PredicateType != trustedsource.SLSAProvenancePredicateType {
			continue
		}
		statement, err := trustedsource.DecodeStatement(attestation.Payload)
		if err != nil {
			return &Error{Code: CodeProvenanceInvalid, Ref: ref, Err: err}
		}
		if err := validateProvenanceBinding(statement, req, expected); err != nil {
			return &Error{Code: CodeProvenanceInvalid, Ref: ref, Err: err}
		}
		return nil
	}
	return &Error{Code: CodeProvenanceInvalid, Ref: ref, Err: errors.New("no SLSA provenance statement matched the required predicate")}
}

func validateProvenanceBinding(statement *trustedsource.Statement, req Request, expected PublisherExpectation) error {
	repository := repositoryFor(req.Artifact.Ref)
	digest := strings.TrimPrefix(req.Artifact.Digest, "sha256:")
	matched := false
	for _, subject := range statement.Subject {
		if subject.Name == repository && subject.Digest["sha256"] == digest {
			matched = true
		}
	}
	if !matched {
		return errors.New("provenance subject does not match the selected repository@digest")
	}
	parameters := statement.Predicate.BuildDefinition.ExternalParameters
	if parameters.Repository != req.Source.Publisher.SourceRepository || parameters.SourceSHA != req.Artifact.SourceSHA {
		return errors.New("provenance source repository/SHA mismatch")
	}
	if parameters.ReleaseTag != req.Artifact.ReleaseTag || parameters.PackageVersion != req.Artifact.PackageVersion {
		return errors.New("provenance release/package version mismatch")
	}
	if parameters.RunID != req.Artifact.Producer.RunID || parameters.RunAttempt != req.Artifact.Producer.RunAttempt {
		return errors.New("provenance run ID/attempt mismatch")
	}
	if req.Source.Publisher.Event != "" && parameters.Event != req.Source.Publisher.Event {
		return errors.New("provenance event mismatch")
	}
	if req.Source.Publisher.SourceRef != "" && parameters.SourceRef != req.Source.Publisher.SourceRef {
		return errors.New("provenance source ref mismatch")
	}
	if req.Source.Publisher.ReleaseEnvironment != "" && parameters.Environment != req.Source.Publisher.ReleaseEnvironment {
		return errors.New("provenance release environment mismatch")
	}
	if statement.Predicate.RunDetails.Builder.ID != expected.WorkflowURI() {
		return errors.New("provenance builder does not match the selected reusable workflow")
	}
	if statement.Predicate.RunDetails.Metadata.InvocationID != req.Artifact.Producer.RunURI {
		return errors.New("provenance invocation does not match the release run")
	}
	dependencyMatched := false
	for _, dependency := range statement.Predicate.BuildDefinition.ResolvedDependencies {
		if dependency.URI == "https://github.com/"+req.Source.Publisher.Repository+"/"+expected.Workflow() && dependency.Digest["sha"] == req.Source.Publisher.WorkflowSHA {
			dependencyMatched = true
		}
	}
	if !dependencyMatched {
		return errors.New("provenance does not pin the selected reusable workflow dependency")
	}
	return nil
}

func (v *Verifier) verifyTestEvidence(ctx context.Context, ref string, req Request, expected PublisherExpectation) (string, error) {
	attestations, err := v.backend.VerifyAttestations(ctx, ref, expected, trustedsource.TestEvidencePredicateType)
	if err != nil {
		return "", admissionBackendError(CodeUnavailable, ref, err)
	}
	if len(attestations) == 0 {
		return "", &Error{Code: CodeTestEvidenceInvalid, Ref: ref, Err: errors.New("missing signed test evidence")}
	}
	for _, attestation := range attestations {
		if attestation.PredicateType != trustedsource.TestEvidencePredicateType {
			continue
		}
		evidence, err := trustedsource.DecodeTestEvidence(attestation.Payload)
		if err != nil {
			return "", &Error{Code: CodeTestEvidenceInvalid, Ref: ref, Err: err}
		}
		maxAge, err := req.Source.PluginCompatibilityAge()
		if err != nil {
			return "", &Error{Code: CodeInvalidRequest, Ref: ref, Err: err}
		}
		if err := evidence.ValidateAt(req.Now, maxAge, req.RequireUICompatibility); err != nil {
			return "", &Error{Code: CodeTestEvidenceInvalid, Ref: ref, Err: err}
		}
		if err := validateEvidenceBinding(evidence, req, expected); err != nil {
			return "", &Error{Code: CodeTestEvidenceInvalid, Ref: ref, Err: err}
		}
		return evidence.EvidenceDigest, nil
	}
	return "", &Error{Code: CodeTestEvidenceInvalid, Ref: ref, Err: errors.New("no test-evidence statement matched the required predicate")}
}

func validateEvidenceBinding(evidence *trustedsource.TestEvidence, req Request, expected PublisherExpectation) error {
	if evidence.App != req.Artifact.App || evidence.Component != req.Artifact.Component {
		return fmt.Errorf("test evidence app/component mismatch")
	}
	if evidence.TrustTier != req.Source.TrustTier {
		return errors.New("test evidence trust tier does not match the server-assigned source tier")
	}
	if evidence.SourceRepository != req.Source.Publisher.SourceRepository || evidence.SourceSHA != req.Artifact.SourceSHA || evidence.ReleaseTag != req.Artifact.ReleaseTag {
		return errors.New("test evidence source or release mismatch")
	}
	if evidence.Artifact.Repository != repositoryFor(req.Artifact.Ref) || evidence.Artifact.Digest != req.Artifact.Digest || evidence.Artifact.MediaType != req.Artifact.MediaType {
		return errors.New("test evidence artifact mismatch")
	}
	producer := evidence.Producer
	if producer.WorkflowPath != expected.Workflow() || producer.WorkflowSHA != req.Source.Publisher.WorkflowSHA {
		return errors.New("test evidence producer workflow mismatch")
	}
	if producer.RunID != req.Artifact.Producer.RunID || producer.RunAttempt != req.Artifact.Producer.RunAttempt || producer.RunURI != req.Artifact.Producer.RunURI {
		return errors.New("test evidence producer run mismatch")
	}
	return nil
}
