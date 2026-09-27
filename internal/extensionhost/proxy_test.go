package extensionhost

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestProxyAuthInjection(t *testing.T) {
	var got struct {
		downstreamAuth string
		authMethod     string
		inboundAuth    string
		apiKey         string
		user           string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.downstreamAuth = r.Header.Get(HeaderDownstreamAuthorization)
		got.authMethod = r.Header.Get(HeaderAuthMethod)
		got.inboundAuth = r.Header.Get("Authorization")
		got.apiKey = r.Header.Get("X-Api-Key")
		got.user = r.Header.Get("X-Inari-User")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ext := &types.Extension{
		ID: "extension:1", OrgID: "org:1", Name: "argocd", Version: "0.1.0",
		Endpoint: upstream.URL, State: types.ExtensionStateReady,
	}
	newRouter := func(m *AuthModel) *chi.Mux {
		p := NewProxy(staticGetter{ext}, fakeValidator{id: &authn.Identity{Subject: "user-1"}}, fakeAuthorizer{allow: true})
		if m != nil {
			p.WithAuthModel(m)
		}
		r := chi.NewRouter()
		p.Mount(r)
		return r
	}
	do := func(r http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/extensions/argocd/applications", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		req.Header.Set("X-Api-Key", "inbound-key")
		req.Header.Set(HeaderDownstreamAuthorization, "Bearer attacker-token")
		req.Header.Set(HeaderAuthMethod, "shared-secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	t.Run("oidc-user injects exchanged token on separate headers", func(t *testing.T) {
		x := &fakeExchanger{token: "exchanged-tok"}
		rec := do(newRouter(NewAuthModel(x, nil)))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d body %q", rec.Code, rec.Body.String())
		}
		if got.downstreamAuth != "Bearer exchanged-tok" {
			t.Errorf("downstream auth = %q", got.downstreamAuth)
		}
		if got.authMethod != string(AuthMethodOIDCUser) {
			t.Errorf("auth method = %q", got.authMethod)
		}
		if got.inboundAuth != "" || got.apiKey != "" {
			t.Errorf("inbound credentials leaked: auth=%q apikey=%q", got.inboundAuth, got.apiKey)
		}
		if got.user != "user-1" {
			t.Errorf("identity user = %q", got.user)
		}
		if x.lastSubjectToken != "user-token" || x.lastAudience != "" {
			t.Errorf("exchange args: subj=%q aud=%q", x.lastSubjectToken, x.lastAudience)
		}
	})

	t.Run("declared audience forwarded to exchanger", func(t *testing.T) {
		e2 := *ext
		e2.Manifest = []byte(`{"auth":{"methods":[{"type":"oidc-user","audience":"argocd-server","isDefault":true}]}}`)
		p := NewProxy(staticGetter{&e2}, fakeValidator{id: &authn.Identity{Subject: "user-1"}}, fakeAuthorizer{allow: true})
		x := &fakeExchanger{token: "t"}
		p.WithAuthModel(NewAuthModel(x, nil))
		r := chi.NewRouter()
		p.Mount(r)
		req := httptest.NewRequest(http.MethodGet, "/api/extensions/argocd/applications", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || x.lastAudience != "argocd-server" {
			t.Fatalf("code=%d aud=%q", rec.Code, x.lastAudience)
		}
	})

	t.Run("exchange denied maps to 403 downstream_permission_denied", func(t *testing.T) {
		rec := do(newRouter(NewAuthModel(&fakeExchanger{err: ErrExchangeDenied}, nil)))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), codeDownstreamPermissionDenied) {
			t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("exchange unavailable maps to 502 auth_unavailable", func(t *testing.T) {
		rec := do(newRouter(NewAuthModel(&fakeExchanger{err: ErrExchangeUnavailable}, nil)))
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), codeAuthUnavailable) {
			t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("unknown declared method fails closed", func(t *testing.T) {
		e2 := *ext
		e2.Manifest = []byte(`{"auth":{"methods":[{"type":"api-key","isDefault":true}]}}`)
		p := NewProxy(staticGetter{&e2}, fakeValidator{id: &authn.Identity{Subject: "user-1"}}, fakeAuthorizer{allow: true})
		p.WithAuthModel(NewAuthModel(&fakeExchanger{}, nil))
		r := chi.NewRouter()
		p.Mount(r)
		req := httptest.NewRequest(http.MethodGet, "/api/extensions/argocd/applications", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), codeAuthUnavailable) {
			t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("sso-session miss maps to 401 reauth_required with provider header", func(t *testing.T) {
		e2 := *ext
		e2.Manifest = []byte(`{"auth":{"methods":[{"type":"oidc-sso-session","audience":"argocd","isDefault":true}]}}`)
		p := NewProxy(staticGetter{&e2}, fakeValidator{id: &authn.Identity{Subject: "user-1"}}, fakeAuthorizer{allow: true})
		p.WithAuthModel(NewAuthModel(&fakeExchanger{}, &fakeSessionStore{err: ErrSessionNotFound}))
		r := chi.NewRouter()
		p.Mount(r)
		req := httptest.NewRequest(http.MethodGet, "/api/extensions/argocd/applications", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), codeReauthRequired) {
			t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
		}
		if rec.Header().Get(HeaderReauth) != "argocd" {
			t.Fatalf("reauth header = %q", rec.Header().Get(HeaderReauth))
		}
	})

	t.Run("fga denial carries distinct code", func(t *testing.T) {
		p := NewProxy(staticGetter{ext}, fakeValidator{id: &authn.Identity{Subject: "user-1"}}, fakeAuthorizer{allow: false})
		r := chi.NewRouter()
		p.Mount(r)
		req := httptest.NewRequest(http.MethodGet, "/api/extensions/argocd/applications", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), codeInariFGADenied) {
			t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("error responses never contain token material", func(t *testing.T) {
		rec := do(newRouter(NewAuthModel(&fakeExchanger{err: errors.New("boom")}, nil)))
		body := rec.Body.String()
		for _, tok := range []string{"user-token", "attacker-token", "inbound-key"} {
			if strings.Contains(body, tok) {
				t.Fatalf("response leaks %q: %q", tok, body)
			}
		}
	})
}
