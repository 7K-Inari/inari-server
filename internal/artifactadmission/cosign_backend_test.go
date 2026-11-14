package artifactadmission

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	gcremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	cosignstatic "github.com/sigstore/cosign/v3/pkg/oci/static"
	cosigntypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/payload"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/oci"
)

type fixtureTrustedMaterial struct {
	*root.BaseTrustedMaterial
	ca     *root.FulcioCertificateAuthority
	logKey crypto.PublicKey
}

func (m *fixtureTrustedMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{m.ca}
}

func (m *fixtureTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{"local": {ID: []byte("local-rekor"), PublicKey: m.logKey}}
}

func (m *fixtureTrustedMaterial) CTLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{"local": {ID: []byte("local-ct"), PublicKey: m.logKey}}
}

type fixtureAuthority struct {
	cert     *x509.Certificate
	certPEM  []byte
	key      *ecdsa.PrivateKey
	material root.TrustedMaterial
}

func newFixtureAuthority(t *testing.T, expected PublisherExpectation) *fixtureAuthority {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Inari test Fulcio CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := certificateForExpectation(t, expected)
	leafTemplate.SerialNumber = big.NewInt(2)
	leafTemplate.Subject = pkix.Name{CommonName: "Inari test workflow"}
	leafTemplate.NotBefore = now.Add(-time.Hour)
	leafTemplate.NotAfter = now.Add(24 * time.Hour)
	leafTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	leafTemplate.BasicConstraintsValid = true
	leafTemplate.Extensions = append(leafTemplate.Extensions,
		certificateExtension(t, certificate.OIDIssuerV2, expected.Source.Publisher.Issuer),
		pkix.Extension{Id: certificate.OIDIssuer, Value: []byte(expected.Source.Publisher.Issuer)})
	leafTemplate.ExtraExtensions = leafTemplate.Extensions
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureAuthority{
		cert:    leafCert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		key:     leafKey,
		material: &fixtureTrustedMaterial{
			BaseTrustedMaterial: &root.BaseTrustedMaterial{},
			ca:                  &root.FulcioCertificateAuthority{Root: caCert},
			logKey:              &leafKey.PublicKey,
		},
	}
}

func writeLocalSignedArtifact(t *testing.T, authority *fixtureAuthority) (name.Digest, string) {
	t.Helper()
	registryServer := httptest.NewServer(registry.New())
	t.Cleanup(registryServer.Close)
	registryURL, err := url.Parse(registryServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(registryURL.Host+"/catalog/web-service:1.2.0", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := gcremote.Write(tag, empty.Image); err != nil {
		t.Fatal(err)
	}
	descriptor, err := gcremote.Head(tag)
	if err != nil {
		t.Fatal(err)
	}
	digest := tag.Context().Digest(descriptor.Digest.String())

	signerVerifier, err := signature.LoadECDSASignerVerifier(authority.key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signingPayload, err := (payload.Cosign{Image: digest}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	rawSignature, err := signerVerifier.SignMessage(bytes.NewReader(signingPayload))
	if err != nil {
		t.Fatal(err)
	}
	ociSignature, err := cosignstatic.NewSignature(signingPayload, base64.StdEncoding.EncodeToString(rawSignature),
		cosignstatic.WithCertChain(authority.certPEM, nil))
	if err != nil {
		t.Fatal(err)
	}
	signedImage := signed.Image(empty.Image)
	signedImage, err = mutate.AttachSignatureToImage(signedImage, ociSignature)
	if err != nil {
		t.Fatal(err)
	}
	if err := cosignremote.WriteSignatures(digest.Context(), signedImage); err != nil {
		t.Fatal(err)
	}

	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": trustedsource.TestEvidencePredicateType,
		"predicate":     map[string]any{"schema": "local-fixture"},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sigdsse.WrapSignerVerifier(signerVerifier, cosigntypes.IntotoPayloadType).SignMessage(bytes.NewReader(statement))
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := cosignstatic.NewSignature(envelope, "", cosignstatic.WithCertChain(authority.certPEM, nil))
	if err != nil {
		t.Fatal(err)
	}
	signedImage, err = mutate.AttachAttestationToImage(signedImage, attestation)
	if err != nil {
		t.Fatal(err)
	}
	if err := cosignremote.WriteAttestations(digest.Context(), signedImage); err != nil {
		t.Fatal(err)
	}
	return digest, registryURL.Host
}

func TestCosignBackendVerifiesLocalSignatureAndAttestation(t *testing.T) {
	req := validRequest()
	expected := PublisherExpectation{Source: req.Source, Role: req.Role, SourceSHA: req.Artifact.SourceSHA, Producer: req.Artifact.Producer}
	authority := newFixtureAuthority(t, expected)
	digest, _ := writeLocalSignedArtifact(t, authority)
	backend := NewCosignBackend(&oci.Fetcher{Insecure: true})
	backend.Insecure = true
	backend.trustedMaterial = authority.material
	backend.ignoreTlogForTest = true
	backend.ignoreSCTForTest = true

	if err := backend.VerifySignature(context.Background(), digest.String(), expected); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	attestations, err := backend.VerifyAttestations(context.Background(), digest.String(), expected, trustedsource.TestEvidencePredicateType)
	if err != nil {
		t.Fatalf("VerifyAttestations: %v", err)
	}
	if len(attestations) != 1 || string(attestations[0].Payload) != `{"schema":"local-fixture"}` {
		t.Fatalf("attestations = %+v", attestations)
	}
}
