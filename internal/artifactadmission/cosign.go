package artifactadmission

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	cosigntypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/oci"
)

var oidDeploymentEnvironment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 23}

// CosignBackend verifies OCI content and keyless signatures/attestations.
// Publisher checks happen after cosign has cryptographically verified each
// signature, never before or instead of that verification.
type CosignBackend struct {
	Fetcher  *oci.Fetcher
	Keychain authn.Keychain
	Insecure bool

	trustedMaterialOnce   sync.Once
	trustedMaterial       root.TrustedMaterial
	trustedMaterialErr    error
	trustedMaterialLoader func() (root.TrustedMaterial, error)
	ignoreTlogForTest     bool
	ignoreSCTForTest      bool
}

func NewCosignBackend(fetcher *oci.Fetcher) *CosignBackend {
	if fetcher == nil {
		fetcher = &oci.Fetcher{}
	}
	return &CosignBackend{Fetcher: fetcher}
}

func (b *CosignBackend) Fetch(ctx context.Context, ref string) (*oci.Artifact, error) {
	return b.Fetcher.Fetch(ctx, ref)
}

func (b *CosignBackend) material() (root.TrustedMaterial, error) {
	b.trustedMaterialOnce.Do(func() {
		if b.trustedMaterial != nil {
			return
		}
		loader := b.trustedMaterialLoader
		if loader == nil {
			loader = cosign.TrustedRoot
		}
		b.trustedMaterial, b.trustedMaterialErr = loader()
	})
	if b.trustedMaterialErr != nil {
		return nil, b.trustedMaterialErr
	}
	if b.trustedMaterial == nil {
		return nil, errors.New("sigstore trusted material is unavailable")
	}
	return b.trustedMaterial, nil
}

func (b *CosignBackend) options(expected PublisherExpectation) ([]name.Option, *cosign.CheckOpts, error) {
	if expected.Source.Publisher.Issuer == "" || expected.Source.Publisher.Repository == "" {
		return nil, nil, &Error{Code: CodeInvalidRequest, Err: errors.New("publisher issuer and repository are required")}
	}
	material, err := b.material()
	if err != nil {
		return nil, nil, &Error{Code: CodeUnavailable, Err: fmt.Errorf("load sigstore trusted material: %w", err), Temporary: true}
	}
	opts := []name.Option{}
	if b.Insecure {
		opts = append(opts, name.Insecure)
	}
	kc := b.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	subject := "^" + regexp.QuoteMeta("https://github.com/"+expected.Source.Publisher.Repository+"/")
	return opts, &cosign.CheckOpts{
		RegistryClientOpts: []cosignremote.Option{cosignremote.WithRemoteOptions(gcremote.WithAuthFromKeychain(kc))},
		Identities:         []cosign.Identity{{SubjectRegExp: subject, Issuer: expected.Source.Publisher.Issuer}},
		TrustedMaterial:    material,
		IgnoreTlog:         b.ignoreTlogForTest,
		IgnoreSCT:          b.ignoreSCTForTest,
		// OCI 1.1 support is required for registry-referrer evidence. The
		// protected producer dogfood validates the exact bundle format.
		ExperimentalOCI11: true,
	}, nil
}

func (b *CosignBackend) VerifySignature(ctx context.Context, ref string, expected PublisherExpectation) error {
	nameOpts, opts, err := b.options(expected)
	if err != nil {
		return err
	}
	r, err := name.ParseReference(ref, nameOpts...)
	if err != nil {
		return &Error{Code: CodeInvalidRequest, Ref: ref, Err: err}
	}
	opts.RegistryClientOpts = append(opts.RegistryClientOpts, cosignremote.WithRemoteOptions(gcremote.WithContext(ctx)))
	signatures, _, err := cosign.VerifyImageSignatures(ctx, r, opts)
	if err != nil {
		return &Error{Code: CodeSignatureInvalid, Ref: ref, Err: err}
	}
	if len(signatures) == 0 {
		return &Error{Code: CodeSignatureInvalid, Ref: ref, Err: errors.New("artifact has no signatures")}
	}
	var validationErrors []error
	for _, signature := range signatures {
		cert, err := signature.Cert()
		if err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}
		if err := validateCertificate(cert, expected); err == nil {
			return nil
		} else {
			validationErrors = append(validationErrors, err)
		}
	}
	return &Error{Code: CodePublisherMismatch, Ref: ref, Err: errors.Join(validationErrors...)}
}

func (b *CosignBackend) VerifyAttestations(ctx context.Context, ref string, expected PublisherExpectation, predicateType string) ([]Attestation, error) {
	nameOpts, opts, err := b.options(expected)
	if err != nil {
		return nil, err
	}
	r, err := name.ParseReference(ref, nameOpts...)
	if err != nil {
		return nil, &Error{Code: CodeInvalidRequest, Ref: ref, Err: err}
	}
	opts.RegistryClientOpts = append(opts.RegistryClientOpts, cosignremote.WithRemoteOptions(gcremote.WithContext(ctx)))
	signatures, _, err := cosign.VerifyImageAttestations(ctx, r, opts, nameOpts...)
	if err != nil {
		return nil, attestationError(predicateType, ref, err)
	}
	var out []Attestation
	var publisherErrors []error
	var evidenceErrors []error
	for _, signature := range signatures {
		cert, err := signature.Cert()
		if err != nil {
			publisherErrors = append(publisherErrors, err)
			continue
		}
		if err := validateCertificate(cert, expected); err != nil {
			publisherErrors = append(publisherErrors, err)
			continue
		}
		payload, err := signature.Payload()
		if err != nil {
			evidenceErrors = append(evidenceErrors, err)
			continue
		}
		verifiedPredicateType, statement, predicate, err := decodeVerifiedAttestation(payload)
		if err != nil {
			evidenceErrors = append(evidenceErrors, err)
			continue
		}
		if verifiedPredicateType != predicateType {
			continue
		}
		evidencePayload := predicate
		if predicateType == trustedsource.SLSAProvenancePredicateType {
			evidencePayload = statement
		}
		out = append(out, Attestation{PredicateType: predicateType, Payload: evidencePayload})
	}
	if len(out) == 0 {
		if len(evidenceErrors) > 0 {
			return nil, attestationError(predicateType, ref, errors.Join(evidenceErrors...))
		}
		if len(publisherErrors) > 0 {
			return nil, &Error{Code: CodePublisherMismatch, Ref: ref, Err: errors.Join(publisherErrors...)}
		}
	}
	return out, nil
}

func isTemporaryRegistryError(err error) bool {
	var temporary interface{ Temporary() bool }
	return errors.As(err, &temporary) && temporary.Temporary()
}

func attestationError(predicateType, ref string, err error) error {
	if isTemporaryRegistryError(err) {
		return &Error{Code: CodeUnavailable, Ref: ref, Err: err, Temporary: true}
	}
	code := CodeSignatureInvalid
	switch predicateType {
	case trustedsource.SLSAProvenancePredicateType:
		code = CodeProvenanceInvalid
	case trustedsource.TestEvidencePredicateType:
		code = CodeTestEvidenceInvalid
	}
	return &Error{Code: code, Ref: ref, Err: err}
}

func decodeVerifiedAttestation(payload []byte) (string, []byte, []byte, error) {
	var envelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return "", nil, nil, fmt.Errorf("decode DSSE envelope: %w", err)
	}
	if envelope.PayloadType != cosigntypes.IntotoPayloadType {
		return "", nil, nil, fmt.Errorf("unexpected DSSE payload type %q", envelope.PayloadType)
	}
	statement, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return "", nil, nil, fmt.Errorf("decode DSSE statement: %w", err)
	}
	var document struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(statement, &document); err != nil {
		return "", nil, nil, fmt.Errorf("decode in-toto statement: %w", err)
	}
	if document.Type != "https://in-toto.io/Statement/v1" {
		return "", nil, nil, fmt.Errorf("unexpected in-toto statement type %q", document.Type)
	}
	if document.PredicateType == "" || len(document.Predicate) == 0 || string(document.Predicate) == "null" {
		return "", nil, nil, errors.New("in-toto predicate and predicateType are required")
	}
	return document.PredicateType, statement, document.Predicate, nil
}

func certificateDeploymentEnvironment(cert *x509.Certificate) (string, error) {
	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(oidDeploymentEnvironment) {
			continue
		}
		var environment string
		if err := certificate.ParseDERString(extension.Value, &environment); err != nil {
			return "", fmt.Errorf("parse deployment environment: %w", err)
		}
		return environment, nil
	}
	return "", nil
}

func validateCertificate(cert *x509.Certificate, expected PublisherExpectation) error {
	if cert == nil {
		return errors.New("signature has no certificate")
	}
	extensions, err := certificate.ParseExtensions(cert.Extensions)
	if err != nil {
		return fmt.Errorf("parse Fulcio extensions: %w", err)
	}
	workflowURI := expected.WorkflowURI()
	sanMatched := false
	for _, uri := range cert.URIs {
		if uri != nil && uri.String() == workflowURI {
			sanMatched = true
		}
	}
	if !sanMatched {
		return fmt.Errorf("certificate SAN does not match %s", workflowURI)
	}
	if extensions.Issuer != "" && extensions.Issuer != expected.Source.Publisher.Issuer {
		return fmt.Errorf("certificate issuer %q does not match %q", extensions.Issuer, expected.Source.Publisher.Issuer)
	}
	if extensions.BuildSignerURI != workflowURI || extensions.BuildSignerDigest != expected.Source.Publisher.WorkflowSHA {
		return errors.New("BuildSigner identity/SHA mismatch")
	}
	sourceURI := "https://github.com/" + expected.Source.Publisher.SourceRepository
	if extensions.SourceRepositoryURI != sourceURI || extensions.SourceRepositoryDigest != expected.SourceSHA {
		return errors.New("source repository/SHA mismatch")
	}
	if extensions.BuildConfigURI != expected.SourceWorkflowURI() || extensions.BuildConfigDigest != expected.SourceSHA {
		return errors.New("BuildConfig workflow/source SHA mismatch")
	}
	if expected.Source.Publisher.Event != "" && extensions.BuildTrigger != expected.Source.Publisher.Event {
		return errors.New("source event mismatch")
	}
	if expected.Source.Publisher.SourceRef != "" && extensions.SourceRepositoryRef != expected.Source.Publisher.SourceRef {
		return errors.New("source ref mismatch")
	}
	if expected.Producer.RunURI != "" {
		if _, err := url.ParseRequestURI(expected.Producer.RunURI); err != nil {
			return fmt.Errorf("invalid producer run URI: %w", err)
		}
		if extensions.RunInvocationURI != expected.Producer.RunURI {
			return errors.New("run invocation mismatch")
		}
	}
	if expected.Source.Publisher.ReleaseEnvironment != "" {
		environment, err := certificateDeploymentEnvironment(cert)
		if err != nil {
			return err
		}
		if environment == "" {
			return errors.New("certificate has no deployment-environment claim")
		}
		if environment != expected.Source.Publisher.ReleaseEnvironment {
			return fmt.Errorf("deployment environment %q does not match %q", environment, expected.Source.Publisher.ReleaseEnvironment)
		}
	}
	return nil
}
