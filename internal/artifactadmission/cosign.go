package artifactadmission

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/7K-Inari/inari-server/internal/oci"
)

// CosignBackend verifies OCI content and keyless signatures/attestations.
// Publisher checks happen after cosign has cryptographically verified each
// signature, never before or instead of that verification.
type CosignBackend struct {
	Fetcher  *oci.Fetcher
	Keychain authn.Keychain
	Insecure bool
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

func (b *CosignBackend) options(expected PublisherExpectation) ([]name.Option, *cosign.CheckOpts, error) {
	if expected.Source.Publisher.Issuer == "" || expected.Source.Publisher.Repository == "" {
		return nil, nil, &Error{Code: CodeInvalidRequest, Err: errors.New("publisher issuer and repository are required")}
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
		return nil, &Error{Code: CodeUnavailable, Ref: ref, Err: err, Temporary: true}
	}
	var out []Attestation
	var validationErrors []error
	for _, signature := range signatures {
		cert, err := signature.Cert()
		if err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}
		if err := validateCertificate(cert, expected); err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}
		payload, err := signature.Payload()
		if err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}
		var envelope struct {
			PredicateType string `json:"predicateType"`
		}
		if err := json.Unmarshal(payload, &envelope); err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}
		if envelope.PredicateType == predicateType {
			out = append(out, Attestation{PredicateType: predicateType, Payload: payload})
		}
	}
	if len(out) == 0 && len(validationErrors) > 0 {
		return nil, &Error{Code: CodePublisherMismatch, Ref: ref, Err: errors.Join(validationErrors...)}
	}
	return out, nil
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
	// GitHub's deployment-environment claim is not standardized in the
	// Fulcio extensions exposed by this cosign version. No alternate field is
	// inferred. Producer fixtures must prove any additional environment claim
	// before it can be enforced here.
	return nil
}
