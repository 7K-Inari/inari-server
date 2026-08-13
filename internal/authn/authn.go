// Package authn validates OIDC JWTs against the Keycloak `inari` realm and
// enforces the coarse PEP: valid token + tenant derived from the
// `organization` claim, never from URL or header.
package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

// Identity is the authenticated caller extracted from the JWT.
type Identity struct {
	Subject      string
	Email        string
	Organizations []string
	Groups       []string
}

// MemberOf reports whether the identity belongs to the given org (slug/alias).
func (i *Identity) MemberOf(org string) bool {
	for _, o := range i.Organizations {
		if o == org {
			return true
		}
	}
	return false
}

// Validator validates a raw bearer token into an Identity.
type Validator interface {
	Validate(ctx context.Context, rawToken string) (*Identity, error)
}

// OIDCValidator validates JWTs via OIDC discovery (JWKS, issuer, audience).
type OIDCValidator struct {
	verifier *oidc.IDTokenVerifier
}

func NewOIDCValidator(ctx context.Context, issuerURL, clientID string) (*OIDCValidator, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("authn: oidc discovery: %w", err)
	}
	return &OIDCValidator{
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

// Claims models the Keycloak token claims we rely on. The `organization`
// claim (from the built-in `organization` scope) is parsed flexibly below.
type Claims struct {
	jwt.RegisteredClaims
	Email        string          `json:"email"`
	Organization json.RawMessage `json:"organization"`
	Groups       []string        `json:"groups"`
}

// ParseOrganizations accepts the Keycloak organization claim as a JSON array
// of aliases, a JSON object keyed by alias, or a single string.
func ParseOrganizations(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		orgs := make([]string, 0, len(obj))
		for k := range obj {
			orgs = append(orgs, k)
		}
		return orgs, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, nil
	}
	return nil, fmt.Errorf("authn: unrecognized organization claim shape")
}

func (v *OIDCValidator) Validate(ctx context.Context, rawToken string) (*Identity, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("authn: token verify: %w", err)
	}
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("authn: claims decode: %w", err)
	}
	orgs, err := ParseOrganizations(claims.Organization)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Subject:       claims.Subject,
		Email:         claims.Email,
		Organizations: orgs,
		Groups:        claims.Groups,
	}, nil
}

type ctxKey struct{}

// IdentityFromContext returns the authenticated identity, or nil.
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(ctxKey{}).(*Identity)
	return id
}

// Middleware authenticates requests with a bearer token and stores the
// Identity in the request context.
func Middleware(v Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := bearerToken(r)
			if err != nil {
				http.Error(w, `{"error":"missing or malformed authorization header"}`, http.StatusUnauthorized)
				return
			}
			id, err := v.Validate(r.Context(), raw)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
		})
	}
}

// RequireOrg is the coarse PEP: the tenant slug in the route must be backed
// by the token's organization claim. The tenant is never taken from the URL
// or a header alone.
func RequireOrg(param string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := IdentityFromContext(r.Context())
			if id == nil {
				http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			org := r.PathValue(param)
			if org == "" || !id.MemberOf(org) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("no authorization header")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", errors.New("malformed authorization header")
	}
	return parts[1], nil
}
