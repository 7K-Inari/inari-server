// Package artifactadmission verifies trusted OCI artifacts at sync and again
// at deploy/render time. Last-good snapshots are availability state, never a
// substitute for current cryptographic and evidence verification.
package artifactadmission

import (
	"errors"
	"fmt"
	"strings"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
)

const (
	CodeDigestMismatch      = "digest_mismatch"
	CodeMediaTypeMismatch   = "media_type_mismatch"
	CodeSignatureInvalid    = "signature_invalid"
	CodePublisherMismatch   = "publisher_mismatch"
	CodeProvenanceInvalid   = "provenance_invalid"
	CodeTestEvidenceInvalid = "test_evidence_invalid"
	CodeUnsignedProduction  = "unsigned_production_denied"
	CodeUnavailable         = "admission_unavailable"
	CodeInvalidRequest      = "invalid_admission_request"
)

type Error struct {
	Code      string
	Ref       string
	Err       error
	Temporary bool
}

func (e *Error) Error() string {
	if e.Ref == "" {
		return fmt.Sprintf("artifact admission: %s: %v", e.Code, e.Err)
	}
	return fmt.Sprintf("artifact admission: %s for %s: %v", e.Code, e.Ref, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func IsCode(err error, code string) bool {
	var admissionErr *Error
	return errors.As(err, &admissionErr) && admissionErr.Code == code
}

func IsTemporary(err error) bool {
	var admissionErr *Error
	return errors.As(err, &admissionErr) && admissionErr.Temporary
}

type PublisherExpectation struct {
	Source    trustedsource.Source
	Role      trustedsource.ArtifactRole
	SourceSHA string
	Producer  trustedsource.Producer
}

func (p PublisherExpectation) Workflow() string {
	return p.Source.Publisher.Workflows.For(p.Role)
}

func (p PublisherExpectation) WorkflowURI() string {
	return "https://github.com/" + p.Source.Publisher.Repository + "/" + p.Workflow() + "@" + p.Source.Publisher.WorkflowSHA
}

func (p PublisherExpectation) SourceWorkflowURI() string {
	return "https://github.com/" + p.Source.Publisher.SourceRepository + "/" + p.Source.Publisher.SourceWorkflow + "@" + p.SourceSHA
}

type ArtifactDescriptor struct {
	Ref            string
	Digest         string
	MediaType      string
	SourceSHA      string
	ReleaseTag     string
	PackageVersion string
	App            string
	Component      string
	Producer       trustedsource.Producer
	Lanes          []trustedsource.Lane
	Compatibility  *trustedsource.Compatibility
	Runtime        *trustedsource.RuntimeEvidence
}

type Request struct {
	Source                 trustedsource.Source
	Role                   trustedsource.ArtifactRole
	Artifact               ArtifactDescriptor
	TargetEnvironment      trustedsource.Environment
	RequireUICompatibility bool
	Now                    time.Time
}

type EvidenceSummary struct {
	Unsigned            bool
	PublisherRepository string
	PublisherWorkflow   string
	ArtifactDigest      string
	ProvenanceDigest    string
	TestEvidenceDigest  string
}

type Attestation struct {
	PredicateType string
	Payload       []byte
}

func repositoryFor(ref string) string {
	if at := strings.Index(ref, "@"); at >= 0 {
		return ref[:at]
	}
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		return ref[:colon]
	}
	return ref
}

func immutableRef(ref, digest string) string {
	return repositoryFor(ref) + "@" + digest
}
