// Authenticated reverse proxy (plan §5.8, ArgoCD proxy-extension model):
// the control plane authenticates the caller, enforces the extension invoke
// relation (fine PEP), strips sensitive inbound headers, injects the Inari
// identity headers, and proxies to the verified sidecar endpoint. Mounted on
// chi directly (like the agent gateway) since it is a wildcard path, not a
// huma operation.
package extensionhost

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/types"
)

// Headers stripped from the inbound request before proxying (the plugin must
// never see control-plane credentials or session state).
var strippedRequestHeaders = []string{
	"Authorization",
	"Cookie",
	"Set-Cookie",
	"X-Api-Key",
	// Inbound identity headers are stripped and re-set from the validated
	// token — a caller must never inject them (X-Inari-Org is only re-set
	// for org-scoped extensions).
	"X-Inari-User",
	"X-Inari-Org",
	// Inbound downstream-credential headers are stripped and re-set only by
	// the auth model (strip-then-inject): a caller must never inject them.
	HeaderDownstreamAuthorization,
	HeaderAuthMethod,
}

// Downstream-credential headers injected by the auth model. Distinct from
// the identity headers so plugins can tell "who the user is" (identity-only
// AuthContext) from "what credential to use downstream" (plan §5.8).
const (
	HeaderDownstreamAuthorization = "X-Inari-Downstream-Authorization"
	HeaderAuthMethod              = "X-Inari-Auth-Method"
	// HeaderReauth signals which third-party provider the user must
	// re-authenticate with (oidc-sso-session bootstrap/expiry).
	HeaderReauth = "X-Inari-Reauth"
)

// Error code strings distinguishing denial kinds for API clients
// (orchestrator/http.go-style typed mapping, on the chi-mounted proxy).
const (
	codeInariFGADenied             = "inari_fga_denied"
	codeDownstreamPermissionDenied = "downstream_permission_denied"
	codeReauthRequired             = "reauth_required"
	codeAuthUnavailable            = "auth_unavailable"
)

// Registry resolves extension names to registry records (Service seam).
type Registry interface {
	GetByName(ctx context.Context, name string) (*types.Extension, error)
}

// Proxy serves /api/extensions/{name}/*.
type Proxy struct {
	reg       Registry
	auth      authn.Validator
	az        authz.Authorizer
	authModel *AuthModel
}

func NewProxy(reg Registry, v authn.Validator, az authz.Authorizer) *Proxy {
	return &Proxy{reg: reg, auth: v, az: az}
}

// WithAuthModel wires per-request downstream credential resolution (token
// exchange / session injection). Nil keeps the identity-only pass-through
// (dev mode without Keycloak exchange configured).
func (p *Proxy) WithAuthModel(m *AuthModel) *Proxy {
	p.authModel = m
	return p
}

// Mount registers the wildcard proxy route on the chi router.
func (p *Proxy) Mount(r chi.Router) {
	r.Handle("/api/extensions/{name}/*", p)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	raw := r.Header.Get("Authorization")
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		http.Error(w, `{"detail":"missing or malformed authorization header"}`, http.StatusUnauthorized)
		return
	}
	id, err := p.auth.Validate(r.Context(), raw[len(prefix):])
	if err != nil {
		http.Error(w, `{"detail":"invalid token"}`, http.StatusUnauthorized)
		return
	}
	name := chi.URLParam(r, "name")
	ext, err := p.reg.GetByName(r.Context(), name)
	if err != nil {
		http.Error(w, `{"detail":"extension not found"}`, http.StatusNotFound)
		return
	}
	if ext.State != types.ExtensionStateReady {
		http.Error(w, `{"detail":"extension unavailable"}`, http.StatusBadGateway)
		return
	}
	allowed, err := p.az.Check(r.Context(), authz.UserObject(id.Subject), authz.RelationInvoke, authz.ExtensionObject(ext.ID))
	if err != nil {
		http.Error(w, `{"detail":"authorization check failed"}`, http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, `{"detail":"forbidden","code":"`+codeInariFGADenied+`"}`, http.StatusForbidden)
		return
	}
	// Resolve the effective downstream auth method and credential (fail
	// closed: no credential, no proxying). The caller's bearer token is used
	// only as the exchange subject token and never reaches the upstream.
	var resolved *ResolvedAuth
	if p.authModel != nil {
		resolved, err = p.authModel.Resolve(r.Context(), ext, id, raw[len(prefix):])
		if err != nil {
			writeProxyAuthError(w, err)
			return
		}
	}
	target, err := url.Parse(ext.Endpoint)
	if err != nil || target.Host == "" {
		http.Error(w, `{"detail":"extension endpoint misconfigured"}`, http.StatusBadGateway)
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = strings.TrimPrefix(pr.Out.URL.Path, "/api/extensions/"+name)
			if pr.Out.URL.Path == "" {
				pr.Out.URL.Path = "/"
			}
			pr.Out.Host = target.Host
			for _, h := range strippedRequestHeaders {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Set("X-Inari-User", id.Subject)
			if ext.OrgID != "" {
				pr.Out.Header.Set("X-Inari-Org", ext.OrgID)
			}
			// Strip-then-inject: credential headers were deleted above; only
			// the resolved credential is re-added, on separate headers.
			if resolved != nil && resolved.DownstreamToken != "" {
				pr.Out.Header.Set(HeaderDownstreamAuthorization, "Bearer "+resolved.DownstreamToken)
				pr.Out.Header.Set(HeaderAuthMethod, string(resolved.Method))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			// Crash isolation: a dead sidecar is a 502, never a panic or a
			// control-plane failure.
			http.Error(w, `{"detail":"extension upstream unavailable"}`, http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// writeProxyAuthError maps auth-model errors to responses (mirrors the
// orchestrator/http.go typed-error pattern). Response bodies never carry
// token material; the re-auth signal is a header + code, not a body echo.
func writeProxyAuthError(w http.ResponseWriter, err error) {
	var reauth *ErrReauthRequired
	switch {
	case errors.As(err, &reauth):
		w.Header().Set(HeaderReauth, reauth.Provider)
		http.Error(w, `{"detail":"re-authentication required","code":"`+codeReauthRequired+`"}`, http.StatusUnauthorized)
	case errors.Is(err, ErrExchangeDenied):
		http.Error(w, `{"detail":"downstream permission denied","code":"`+codeDownstreamPermissionDenied+`"}`, http.StatusForbidden)
	case errors.Is(err, ErrExchangeUnavailable), errors.Is(err, ErrAuthMethodUnavailable):
		http.Error(w, `{"detail":"extension auth unavailable","code":"`+codeAuthUnavailable+`"}`, http.StatusBadGateway)
	default:
		http.Error(w, `{"detail":"extension auth failed","code":"`+codeAuthUnavailable+`"}`, http.StatusBadGateway)
	}
}
