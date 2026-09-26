package extensionhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeSecretResolver struct {
	secret string
	err    error
}

func (f *fakeSecretResolver) ClientSecret(context.Context, string) (string, error) {
	return f.secret, f.err
}

func newExchangeFake(t *testing.T, status int, body any) (*httptest.Server, *url.Values) {
	t.Helper()
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		got = r.Form
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func newTestExchanger(srv *httptest.Server, secrets ClientSecretResolver) *KeycloakExchanger {
	u := "http://127.0.0.1:0"
	if srv != nil {
		u = srv.URL
	}
	e := NewKeycloakExchanger(u, secrets)
	e.tokenURL = u
	return e
}

func TestKeycloakExchangeSuccess(t *testing.T) {
	srv, form := newExchangeFake(t, http.StatusOK, map[string]any{"access_token": "downstream-tok", "expires_in": 300})
	e := newTestExchanger(srv, &fakeSecretResolver{secret: "s3cret"})

	tok, err := e.Exchange(context.Background(), "argocd", "subject-tok", "argocd-aud", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if tok != "downstream-tok" {
		t.Fatalf("got %q", tok)
	}
	f := *form
	if f.Get("grant_type") != tokenExchangeGrantType {
		t.Errorf("grant_type %q", f.Get("grant_type"))
	}
	if f.Get("client_id") != "ext-argocd" || f.Get("client_secret") != "s3cret" {
		t.Errorf("client auth wrong: %q", f.Get("client_id"))
	}
	if f.Get("subject_token") != "subject-tok" || f.Get("subject_token_type") != tokenTypeAccessToken {
		t.Errorf("subject token fields wrong")
	}
	if f.Get("audience") != "argocd-aud" || f.Get("scope") != "openid" {
		t.Errorf("audience/scope wrong: %q %q", f.Get("audience"), f.Get("scope"))
	}
}

func TestKeycloakExchangeDenied(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		srv, _ := newExchangeFake(t, status, map[string]any{"error": "access_denied"})
		e := newTestExchanger(srv, &fakeSecretResolver{secret: "x"})
		_, err := e.Exchange(context.Background(), "argocd", "tok", "aud", nil)
		if !errors.Is(err, ErrExchangeDenied) {
			t.Fatalf("status %d: got %v, want ErrExchangeDenied", status, err)
		}
	}
}

func TestKeycloakExchangeUnavailable(t *testing.T) {
	srv, _ := newExchangeFake(t, http.StatusInternalServerError, nil)
	e := newTestExchanger(srv, &fakeSecretResolver{secret: "x"})
	_, err := e.Exchange(context.Background(), "argocd", "tok", "aud", nil)
	if !errors.Is(err, ErrExchangeUnavailable) {
		t.Fatalf("got %v, want ErrExchangeUnavailable", err)
	}

	srv.Close() // network failure
	e = newTestExchanger(srv, &fakeSecretResolver{secret: "x"})
	_, err = e.Exchange(context.Background(), "argocd", "tok", "aud", nil)
	if !errors.Is(err, ErrExchangeUnavailable) {
		t.Fatalf("network: got %v, want ErrExchangeUnavailable", err)
	}
}

func TestKeycloakExchangeEmptySubjectToken(t *testing.T) {
	e := newTestExchanger(nil, &fakeSecretResolver{secret: "x"})
	_, err := e.Exchange(context.Background(), "argocd", "", "aud", nil)
	if !errors.Is(err, ErrExchangeDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestKeycloakExchangeErrorsNeverLeakTokens(t *testing.T) {
	srv, _ := newExchangeFake(t, http.StatusForbidden, map[string]any{"error": "access_denied", "error_description": "subject-tok is invalid"})
	e := newTestExchanger(srv, &fakeSecretResolver{secret: "x"})
	_, err := e.Exchange(context.Background(), "argocd", "subject-tok", "aud", nil)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "subject-tok") {
		t.Fatalf("error leaks token material: %v", err)
	}
}

func TestKeycloakExchangeCache(t *testing.T) {
	srv, _ := newExchangeFake(t, http.StatusOK, map[string]any{"access_token": "tok1", "expires_in": 300})
	calls := 0
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok1", "expires_in": 300})
	})
	e := newTestExchanger(srv, &fakeSecretResolver{secret: "x"})
	now := time.Now()
	e.now = func() time.Time { return now }
	e.WithSubjectKey(func(string) string { return "user-1" })

	ctx := context.Background()
	if _, err := e.Exchange(ctx, "argocd", "tok", "aud", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Exchange(ctx, "argocd", "tok", "aud", nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("cache miss: %d calls", calls)
	}

	// Different audience or extension => different cache entry.
	if _, err := e.Exchange(ctx, "argocd", "tok", "other-aud", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Exchange(ctx, "other-ext", "tok", "aud", nil); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("key separation: %d calls", calls)
	}

	// TTL capped at 60s even though token exp is 300s.
	now = now.Add(61 * time.Second)
	if _, err := e.Exchange(ctx, "argocd", "tok", "aud", nil); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("TTL cap: %d calls", calls)
	}
}

func TestKeycloakExchangeCacheShortExpiry(t *testing.T) {
	srv, _ := newExchangeFake(t, http.StatusOK, nil)
	calls := 0
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 10})
	})
	e := newTestExchanger(srv, &fakeSecretResolver{secret: "x"})
	now := time.Now()
	e.now = func() time.Time { return now }
	e.WithSubjectKey(func(string) string { return "user-1" })
	ctx := context.Background()
	_, _ = e.Exchange(ctx, "argocd", "tok", "aud", nil)
	now = now.Add(11 * time.Second) // min(exp=10s, 60s) = 10s
	_, _ = e.Exchange(ctx, "argocd", "tok", "aud", nil)
	if calls != 2 {
		t.Fatalf("short expiry not honored: %d calls", calls)
	}
}

func TestKeycloakExchangeSecretFailure(t *testing.T) {
	e := newTestExchanger(nil, &fakeSecretResolver{err: errors.New("keycloak down")})
	_, err := e.Exchange(context.Background(), "argocd", "tok", "aud", nil)
	if !errors.Is(err, ErrExchangeUnavailable) {
		t.Fatalf("got %v", err)
	}
}
