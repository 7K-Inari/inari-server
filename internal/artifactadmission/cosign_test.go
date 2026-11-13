package artifactadmission

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

func certificateExtension(t *testing.T, oid asn1.ObjectIdentifier, value string) pkix.Extension {
	t.Helper()
	raw, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oid, Value: raw}
}

func certificateForExpectation(t *testing.T, expected PublisherExpectation) *x509.Certificate {
	t.Helper()
	workflow, _ := url.Parse(expected.WorkflowURI())
	return &x509.Certificate{
		URIs: []*url.URL{workflow},
		Extensions: []pkix.Extension{
			certificateExtension(t, certificate.OIDBuildSignerURI, expected.WorkflowURI()),
			certificateExtension(t, certificate.OIDBuildSignerDigest, expected.Source.Publisher.WorkflowSHA),
			certificateExtension(t, certificate.OIDSourceRepositoryURI, "https://github.com/"+expected.Source.Publisher.SourceRepository),
			certificateExtension(t, certificate.OIDSourceRepositoryDigest, expected.SourceSHA),
			certificateExtension(t, certificate.OIDBuildConfigURI, expected.SourceWorkflowURI()),
			certificateExtension(t, certificate.OIDBuildConfigDigest, expected.SourceSHA),
			certificateExtension(t, certificate.OIDBuildTrigger, expected.Source.Publisher.Event),
			certificateExtension(t, certificate.OIDSourceRepositoryRef, expected.Source.Publisher.SourceRef),
			certificateExtension(t, certificate.OIDRunInvocationURI, expected.Producer.RunURI),
		},
	}
}

func TestValidateCertificate(t *testing.T) {
	req := validRequest()
	expected := PublisherExpectation{Source: req.Source, Role: req.Role, SourceSHA: req.Artifact.SourceSHA, Producer: req.Artifact.Producer}
	cert := certificateForExpectation(t, expected)
	if err := validateCertificate(cert, expected); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
}

func TestValidateCertificateNegatives(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{"san", func(c *x509.Certificate) { c.URIs = nil }},
		{"build signer", func(c *x509.Certificate) {
			c.Extensions[0] = certificateExtension(t, certificate.OIDBuildSignerURI, "https://github.com/other/workflow@main")
		}},
		{"source repository", func(c *x509.Certificate) {
			c.Extensions[2] = certificateExtension(t, certificate.OIDSourceRepositoryURI, "https://github.com/other/repo")
		}},
		{"source sha", func(c *x509.Certificate) {
			c.Extensions[3] = certificateExtension(t, certificate.OIDSourceRepositoryDigest, testSHA)
		}},
		{"build config", func(c *x509.Certificate) {
			c.Extensions[4] = certificateExtension(t, certificate.OIDBuildConfigURI, "https://github.com/other/workflow@main")
		}},
		{"event", func(c *x509.Certificate) {
			c.Extensions[6] = certificateExtension(t, certificate.OIDBuildTrigger, "pull_request")
		}},
		{"source ref", func(c *x509.Certificate) {
			c.Extensions[7] = certificateExtension(t, certificate.OIDSourceRepositoryRef, "refs/heads/unprotected")
		}},
		{"run", func(c *x509.Certificate) {
			c.Extensions[8] = certificateExtension(t, certificate.OIDRunInvocationURI, "https://github.com/other/actions/runs/999")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			expected := PublisherExpectation{Source: req.Source, Role: req.Role, SourceSHA: req.Artifact.SourceSHA, Producer: req.Artifact.Producer}
			cert := certificateForExpectation(t, expected)
			tc.mutate(cert)
			if err := validateCertificate(cert, expected); err == nil {
				t.Fatal("expected certificate mismatch")
			}
		})
	}
}
