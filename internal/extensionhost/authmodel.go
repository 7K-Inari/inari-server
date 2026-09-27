// Extension auth model (plan §5.8, extension OIDC pass-through): how an
// extension's downstream calls are authenticated on behalf of the user.
// Extensions declare supported methods (inari.plugin.v1 AuthMethod, mirrored
// in the registration manifest under auth.methods); the host resolves the
// effective method per request and injects the resulting credential
// out-of-band (proxy headers) — AuthContext stays identity-only.
//
// Security invariants:
//   - Extensions declaring no methods default to oidc-user.
//   - Resolution failures fail closed (no request is proxied without the
//     declared credential).
//   - No built-in static/shared-credential provider ships here: api-key,
//     service-account, and shared-secret are pluggable extension points only,
//     so there is no silent downgrade path.
package extensionhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	pluginv1 "github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/types"
)

// AuthMethod names mirror plugin.v1 AuthMethod_Type (kebab-case for manifest
// JSON). Keep in sync with AuthMethodFromPluginType.
type AuthMethod string

const (
	AuthMethodOIDCUser       AuthMethod = "oidc-user"
	AuthMethodOIDCSSOSession AuthMethod = "oidc-sso-session"
	AuthMethodServiceAccount AuthMethod = "service-account"
	AuthMethodAPIKey         AuthMethod = "api-key"
	AuthMethodSharedSecret   AuthMethod = "shared-secret"
)

// ErrAuthMethodUnavailable fails closed when the effective auth method cannot
// be resolved (undeclared/unknown method, unparsable manifest, or no provider
// registered for a pluggable method).
var ErrAuthMethodUnavailable = errors.New("extensionhost: auth method unavailable")

// AuthMethodFromPluginType maps the generated plugin.v1 enum to the manifest
// name. TYPE_UNSPECIFIED maps to the empty method.
func AuthMethodFromPluginType(t pluginv1.AuthMethod_Type) AuthMethod {
	switch t {
	case pluginv1.AuthMethod_TYPE_OIDC_USER:
		return AuthMethodOIDCUser
	case pluginv1.AuthMethod_TYPE_OIDC_SSO_SESSION:
		return AuthMethodOIDCSSOSession
	case pluginv1.AuthMethod_TYPE_SERVICE_ACCOUNT:
		return AuthMethodServiceAccount
	case pluginv1.AuthMethod_TYPE_API_KEY:
		return AuthMethodAPIKey
	case pluginv1.AuthMethod_TYPE_SHARED_SECRET:
		return AuthMethodSharedSecret
	default:
		return ""
	}
}

// DeclaredAuthMethod is one auth method an extension accepts for downstream
// calls (capability declaration only — the host performs any exchange).
type DeclaredAuthMethod struct {
	Method    AuthMethod
	Audience  string
	Scopes    []string
	IsDefault bool
}

// manifestAuth is the registration-manifest declaration shape
// (auth.methods), additive to the manifest contract.
type manifestAuth struct {
	Auth struct {
		Methods []struct {
			Type      string   `json:"type"`
			Audience  string   `json:"audience"`
			Scopes    []string `json:"scopes"`
			IsDefault bool     `json:"isDefault"`
		} `json:"methods"`
	} `json:"auth"`
}

// declaredAuthMethods parses the extension manifest's auth.methods. A nil or
// declaration-free manifest defaults to oidc-user; invalid JSON fails closed
// (returns nil — pickAuthMethod surfaces ErrAuthMethodUnavailable).
func declaredAuthMethods(ext *types.Extension) []DeclaredAuthMethod {
	if len(ext.Manifest) == 0 {
		return []DeclaredAuthMethod{{Method: AuthMethodOIDCUser, IsDefault: true}}
	}
	var m manifestAuth
	if err := json.Unmarshal(ext.Manifest, &m); err != nil {
		return nil
	}
	out := make([]DeclaredAuthMethod, 0, len(m.Auth.Methods))
	for _, d := range m.Auth.Methods {
		out = append(out, DeclaredAuthMethod{
			Method:    AuthMethod(d.Type),
			Audience:  d.Audience,
			Scopes:    d.Scopes,
			IsDefault: d.IsDefault,
		})
	}
	if len(out) == 0 {
		return []DeclaredAuthMethod{{Method: AuthMethodOIDCUser, IsDefault: true}}
	}
	return out
}

// pickAuthMethod selects the effective method: the declared default, else the
// first entry. Unparsable manifests fail closed.
func pickAuthMethod(ext *types.Extension) (DeclaredAuthMethod, error) {
	methods := declaredAuthMethods(ext)
	if len(methods) == 0 {
		return DeclaredAuthMethod{}, fmt.Errorf("%w: invalid auth declaration", ErrAuthMethodUnavailable)
	}
	for _, m := range methods {
		if m.IsDefault {
			return m, nil
		}
	}
	return methods[0], nil
}

// ConnectionRequest carries the identity-only context a ConnectionProvider
// resolves credentials from. SubjectToken is the caller's validated bearer
// token, used only as the RFC 8693 subject token; it is never persisted or
// logged.
type ConnectionRequest struct {
	Extension    *types.Extension
	Identity     *authn.Identity
	Declared     DeclaredAuthMethod
	SubjectToken string
}

// ResolvedAuth is the in-memory result of auth resolution. DownstreamToken
// is never persisted, logged, or exposed via the API.
type ResolvedAuth struct {
	Method          AuthMethod
	Audience        string
	DownstreamToken string
}

// ConnectionProvider resolves downstream credentials for one auth method.
// Built-in providers cover oidc-user (RFC 8693 exchange) and
// oidc-sso-session (per-user third-party sessions); service-account, api-key,
// and shared-secret are pluggable via RegisterProvider.
type ConnectionProvider interface {
	Name() AuthMethod
	Resolve(ctx context.Context, req ConnectionRequest) (*ResolvedAuth, error)
}

// AuthModel resolves the effective downstream auth for a proxied extension
// call: manifest declaration → provider registry → credential.
type AuthModel struct {
	exchanger TokenExchanger
	sessions  SessionStore
	providers map[AuthMethod]ConnectionProvider
}

// NewAuthModel builds the registry with the built-in providers. exchanger
// backs oidc-user; sessions backs oidc-sso-session (nil store ⇒ declaring
// extensions fail closed with re-auth required until W3 wires the table).
func NewAuthModel(exchanger TokenExchanger, sessions SessionStore) *AuthModel {
	m := &AuthModel{
		exchanger: exchanger,
		sessions:  sessions,
		providers: map[AuthMethod]ConnectionProvider{},
	}
	m.providers[AuthMethodOIDCUser] = &oidcUserProvider{exchanger: exchanger}
	m.providers[AuthMethodOIDCSSOSession] = &ssoSessionProvider{sessions: sessions}
	return m
}

// RegisterProvider plugs in a provider for an extension-defined method
// (service-account/api-key/shared-secret), overriding any built-in.
func (m *AuthModel) RegisterProvider(p ConnectionProvider) {
	m.providers[p.Name()] = p
}

// Resolve returns the credential for the extension's effective auth method.
// Fail closed: any resolution problem is an error, never a silent fallback.
func (m *AuthModel) Resolve(ctx context.Context, ext *types.Extension, id *authn.Identity, subjectToken string) (*ResolvedAuth, error) {
	declared, err := pickAuthMethod(ext)
	if err != nil {
		return nil, err
	}
	p, ok := m.providers[declared.Method]
	if !ok {
		return nil, fmt.Errorf("%w: no provider registered for %s", ErrAuthMethodUnavailable, declared.Method)
	}
	// Audience separation: an oidc-user audience must be on the extension's
	// declared allowlist (defends the exchanger against a drifted pick).
	if declared.Method == AuthMethodOIDCUser && declared.Audience != "" {
		allowed := false
		for _, a := range exchangeAudiences(ext) {
			if a == declared.Audience {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: %s", ErrExchangeAudienceNotAllowed, declared.Audience)
		}
	}
	res, err := p.Resolve(ctx, ConnectionRequest{
		Extension: ext, Identity: id, Declared: declared, SubjectToken: subjectToken,
	})
	if err != nil {
		return nil, err
	}
	// Fail closed: a provider that resolves no credential must not silently
	// proxy the request unauthenticated.
	if res == nil || res.DownstreamToken == "" {
		return nil, fmt.Errorf("%w: provider %s resolved no credential", ErrAuthMethodUnavailable, declared.Method)
	}
	res.Method = declared.Method
	return res, nil
}

// oidcUserProvider exchanges the caller's token per RFC 8693 for a
// downstream-scoped token (audience from the declaration's allowlist).
type oidcUserProvider struct {
	exchanger TokenExchanger
}

func (p *oidcUserProvider) Name() AuthMethod { return AuthMethodOIDCUser }

func (p *oidcUserProvider) Resolve(ctx context.Context, req ConnectionRequest) (*ResolvedAuth, error) {
	if p.exchanger == nil {
		return nil, fmt.Errorf("%w: token exchanger not configured", ErrAuthMethodUnavailable)
	}
	token, err := p.exchanger.Exchange(ctx, req.Extension.Name, req.SubjectToken, req.Declared.Audience, req.Declared.Scopes)
	if err != nil {
		return nil, err
	}
	return &ResolvedAuth{Audience: req.Declared.Audience, DownstreamToken: token}, nil
}
