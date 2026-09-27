package extensionhost

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/types"
)

type emptyTokenProvider struct{}

func (emptyTokenProvider) Name() AuthMethod { return AuthMethodAPIKey }
func (emptyTokenProvider) Resolve(context.Context, ConnectionRequest) (*ResolvedAuth, error) {
	return &ResolvedAuth{}, nil
}

// A pluggable provider that resolves successfully but yields no credential
// must fail closed, not proxy the request unauthenticated.
func TestAuthModelEmptyCredentialFailsClosed(t *testing.T) {
	m := NewAuthModel(&fakeExchanger{token: "t"}, nil)
	m.RegisterProvider(emptyTokenProvider{})
	ext := &types.Extension{
		Name:     "ext",
		Manifest: []byte(`{"auth":{"methods":[{"type":"api-key","isDefault":true}]}}`),
	}
	_, err := m.Resolve(context.Background(), ext, &authn.Identity{Subject: "u"}, "tok")
	if !errors.Is(err, ErrAuthMethodUnavailable) {
		t.Fatalf("err = %v, want ErrAuthMethodUnavailable", err)
	}
}

func TestProxyEmptyCredentialProviderNotProxied(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ext := &types.Extension{
		ID: "extension:1", OrgID: "org:1", Name: "ext", Version: "0.1.0",
		Endpoint: upstream.URL, State: types.ExtensionStateReady,
		Manifest: []byte(`{"auth":{"methods":[{"type":"api-key","isDefault":true}]}}`),
	}
	m := NewAuthModel(&fakeExchanger{token: "t"}, nil)
	m.RegisterProvider(emptyTokenProvider{})
	p := NewProxy(staticGetter{ext}, fakeValidator{id: &authn.Identity{Subject: "u"}}, fakeAuthorizer{allow: true})
	p.WithAuthModel(m)
	r := chi.NewRouter()
	p.Mount(r)
	req := httptest.NewRequest(http.MethodGet, "/api/extensions/ext/x", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if reached {
		t.Fatal("request reached upstream without a resolved credential")
	}
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), codeAuthUnavailable) {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}
