package extensionhost

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	pluginv1 "github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/types"
)

func extWithManifest(t *testing.T, manifest string) *types.Extension {
	t.Helper()
	e := &types.Extension{ID: "ext-1", Name: "argocd", State: types.ExtensionStateReady}
	if manifest != "" {
		e.Manifest = json.RawMessage(manifest)
	}
	return e
}

func TestAuthMethodFromPluginType(t *testing.T) {
	cases := map[pluginv1.AuthMethod_Type]AuthMethod{
		pluginv1.AuthMethod_TYPE_OIDC_USER:        AuthMethodOIDCUser,
		pluginv1.AuthMethod_TYPE_OIDC_SSO_SESSION: AuthMethodOIDCSSOSession,
		pluginv1.AuthMethod_TYPE_SERVICE_ACCOUNT:  AuthMethodServiceAccount,
		pluginv1.AuthMethod_TYPE_API_KEY:          AuthMethodAPIKey,
		pluginv1.AuthMethod_TYPE_SHARED_SECRET:    AuthMethodSharedSecret,
		pluginv1.AuthMethod_TYPE_UNSPECIFIED:      "",
	}
	for in, want := range cases {
		if got := AuthMethodFromPluginType(in); got != want {
			t.Errorf("AuthMethodFromPluginType(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestDeclaredAuthMethods(t *testing.T) {
	t.Run("no manifest defaults to oidc-user", func(t *testing.T) {
		got := declaredAuthMethods(extWithManifest(t, ""))
		if len(got) != 1 || got[0].Method != AuthMethodOIDCUser || !got[0].IsDefault {
			t.Fatalf("got %+v, want single default oidc-user", got)
		}
	})
	t.Run("manifest without auth defaults to oidc-user", func(t *testing.T) {
		got := declaredAuthMethods(extWithManifest(t, `{"displayName":"ArgoCD"}`))
		if len(got) != 1 || got[0].Method != AuthMethodOIDCUser {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("declared methods parsed with default selection", func(t *testing.T) {
		e := extWithManifest(t, `{"auth":{"methods":[
			{"type":"oidc-user","audience":"argocd","scopes":["openid"]},
			{"type":"oidc-sso-session","isDefault":true}]}}`)
		got := declaredAuthMethods(e)
		if len(got) != 2 {
			t.Fatalf("got %+v", got)
		}
		if got[0].Method != AuthMethodOIDCUser || got[0].Audience != "argocd" || got[0].IsDefault {
			t.Fatalf("method 0: %+v", got[0])
		}
		if got[1].Method != AuthMethodOIDCSSOSession || !got[1].IsDefault {
			t.Fatalf("method 1: %+v", got[1])
		}
	})
	t.Run("invalid manifest fails closed", func(t *testing.T) {
		e := extWithManifest(t, `{not json`)
		_, err := pickAuthMethod(e)
		if !errors.Is(err, ErrAuthMethodUnavailable) {
			t.Fatalf("got %v, want ErrAuthMethodUnavailable", err)
		}
	})
}

type stubProvider struct {
	method AuthMethod
	out    *ResolvedAuth
	err    error
	called bool
}

func (s *stubProvider) Name() AuthMethod { return s.method }
func (s *stubProvider) Resolve(context.Context, ConnectionRequest) (*ResolvedAuth, error) {
	s.called = true
	return s.out, s.err
}

func TestAuthModelResolve(t *testing.T) {
	id := &authn.Identity{Subject: "user-1"}
	ctx := context.Background()

	t.Run("default oidc-user uses exchanger", func(t *testing.T) {
		x := &fakeExchanger{token: "tok", err: nil}
		m := NewAuthModel(x, nil)
		got, err := m.Resolve(ctx, extWithManifest(t, ""), id, "subj-token")
		if err != nil {
			t.Fatal(err)
		}
		if got.Method != AuthMethodOIDCUser || got.DownstreamToken != "tok" {
			t.Fatalf("got %+v", got)
		}
		if x.lastSubjectToken != "subj-token" {
			t.Fatalf("exchanger saw %q", x.lastSubjectToken)
		}
	})

	t.Run("unknown method fails closed", func(t *testing.T) {
		m := NewAuthModel(&fakeExchanger{}, nil)
		e := extWithManifest(t, `{"auth":{"methods":[{"type":"api-key","isDefault":true}]}}`)
		_, err := m.Resolve(ctx, e, id, "subj")
		if !errors.Is(err, ErrAuthMethodUnavailable) {
			t.Fatalf("got %v, want ErrAuthMethodUnavailable", err)
		}
	})

	t.Run("registered provider is used", func(t *testing.T) {
		p := &stubProvider{method: AuthMethodAPIKey, out: &ResolvedAuth{Method: AuthMethodAPIKey, DownstreamToken: "k"}}
		m := NewAuthModel(&fakeExchanger{}, nil)
		m.RegisterProvider(p)
		e := extWithManifest(t, `{"auth":{"methods":[{"type":"api-key","isDefault":true}]}}`)
		got, err := m.Resolve(ctx, e, id, "subj")
		if err != nil || !p.called {
			t.Fatalf("got %+v err %v called %v", got, err, p.called)
		}
		if got.DownstreamToken != "k" {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("provider error fails closed", func(t *testing.T) {
		p := &stubProvider{method: AuthMethodAPIKey, err: errors.New("boom")}
		m := NewAuthModel(&fakeExchanger{}, nil)
		m.RegisterProvider(p)
		e := extWithManifest(t, `{"auth":{"methods":[{"type":"api-key","isDefault":true}]}}`)
		_, err := m.Resolve(ctx, e, id, "subj")
		if err == nil {
			t.Fatal("want error")
		}
	})

	t.Run("exchange error propagates", func(t *testing.T) {
		m := NewAuthModel(&fakeExchanger{err: ErrExchangeDenied}, nil)
		_, err := m.Resolve(ctx, extWithManifest(t, ""), id, "subj")
		if !errors.Is(err, ErrExchangeDenied) {
			t.Fatalf("got %v", err)
		}
	})
}

type fakeExchanger struct {
	token            string
	err              error
	calls            int
	lastSubjectToken string
	lastAudience     string
}

func (f *fakeExchanger) Exchange(_ context.Context, _, subjectToken, audience string, _ []string) (string, error) {
	f.calls++
	f.lastSubjectToken = subjectToken
	f.lastAudience = audience
	return f.token, f.err
}
