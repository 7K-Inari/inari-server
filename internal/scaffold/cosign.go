// Cosign keyless signature verification for template artifacts (M8.W6):
// the same trust model as the server image pipeline — keyless signatures
// checked against a configurable certificate-identity regexp and OIDC
// issuer (the template publish pipeline's GitHub Actions identity).
package scaffold

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
)

// CosignVerifier verifies cosign keyless signatures on template
// artifacts. CertIdentityRegexp constrains the signing identity (e.g.
// "^https://github.com/7K-Inari/inari-templates/.github/workflows/publish")
// and CertOidcIssuerRegexp the OIDC issuer (default: GitHub's).
type CosignVerifier struct {
	CertIdentityRegexp   string
	CertOidcIssuerRegexp string
	// Keychain overrides registry auth (default: authn.DefaultKeychain).
	Keychain authn.Keychain
	// Insecure allows plain-HTTP registries (tests/dev).
	Insecure bool
}

// Verify implements SignatureVerifier: the artifact must carry at least
// one valid keyless signature matching the configured identity/issuer.
func (v *CosignVerifier) Verify(ctx context.Context, ref string) error {
	opts := []name.Option{}
	if v.Insecure {
		opts = append(opts, name.Insecure)
	}
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return fmt.Errorf("scaffold: cosign: parse ref %q: %w", ref, err)
	}
	kc := v.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	identity := v.CertIdentityRegexp
	if identity == "" {
		return errors.New("scaffold: cosign: cert identity regexp is required (INARI_SCAFFOLD_TEMPLATE_COSIGN_IDENTITY)")
	}
	issuer := v.CertOidcIssuerRegexp
	if issuer == "" {
		issuer = "^https://token.actions.githubusercontent.com$"
	}
	sigs, _, err := cosign.VerifyImageSignatures(ctx, r, &cosign.CheckOpts{
		RegistryClientOpts: []remote.Option{remote.WithRemoteOptions(gcremote.WithAuthFromKeychain(kc))},
		Identities:         []cosign.Identity{{SubjectRegExp: identity, IssuerRegExp: issuer}},
	})
	if err != nil {
		return fmt.Errorf("scaffold: cosign: verify %s: %w", ref, err)
	}
	if len(sigs) == 0 {
		return fmt.Errorf("scaffold: cosign: %s has no signatures", ref)
	}
	return nil
}
