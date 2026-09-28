package usergit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeGitHub stands in for both the OAuth web endpoints and the API
// endpoints on one httptest server.
type fakeGitHub struct {
	srv *httptest.Server
	// recorded requests
	lastTokenForm url.Values
	revokeCalled  bool
	revokeAuth    string
	// knobs
	tokenErr  string // OAuth error code to return from the token endpoint
	tokenJSON map[string]any
	userLogin string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{userLogin: "octocat"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/login/oauth/access_token":
			_ = r.ParseForm()
			f.lastTokenForm = r.Form
			if f.tokenErr != "" {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": f.tokenErr})
				return
			}
			if f.tokenJSON != nil {
				_ = json.NewEncoder(w).Encode(f.tokenJSON)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ghu_access", "refresh_token": "ghr_refresh",
				"expires_in": 3600, "scope": "repo read:user",
			})
		case r.URL.Path == "/user":
			if r.Header.Get("Authorization") != "Bearer ghu_access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"login": f.userLogin})
		case strings.HasPrefix(r.URL.Path, "/applications/") && strings.HasSuffix(r.URL.Path, "/grant"):
			f.revokeCalled = true
			f.revokeAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) provider(t *testing.T) *GitHubProvider {
	t.Helper()
	p, err := NewGitHubProvider(GitHubConfig{
		ClientID:        "Iv1.test",
		ClientSecret:    "secret",
		CallbackURL:     "https://inari.example/api/v1/tenants/acme/git-connections/github/callback",
		Scopes:          "repo read:user",
		AllowedAPIBases: []string{f.srv.URL},
		HTTPClient:      f.srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGitHubAuthorizeURL(t *testing.T) {
	p, err := NewGitHubProvider(GitHubConfig{
		ClientID: "Iv1.test", ClientSecret: "s", CallbackURL: "https://cb.example/cb", Scopes: "repo",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := p.AuthorizeURL("state-1", "challenge-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, "https://github.com/login/oauth/authorize?") {
		t.Fatalf("url = %q", u)
	}
	for _, want := range []string{"client_id=Iv1.test", "state=state-1", "code_challenge=challenge-1",
		"code_challenge_method=S256", "redirect_uri=" + url.QueryEscape("https://cb.example/cb")} {
		if !strings.Contains(u, want) {
			t.Errorf("url missing %q: %s", want, u)
		}
	}
}

func TestGitHubAuthorizeURLRejectsUnlistedBase(t *testing.T) {
	p, err := NewGitHubProvider(GitHubConfig{ClientID: "x", ClientSecret: "y"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.AuthorizeURL("s", "c", "https://evil.example/api/v3"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
	if _, err := p.AuthorizeURL("s", "c", "http://ghe.example/api/v3"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("http base: err = %v, want ErrInvalidInput", err)
	}
}

func TestGitHubExchange(t *testing.T) {
	f := newFakeGitHub(t)
	p := f.provider(t)
	grant, err := p.Exchange(context.Background(), "code-1", "verifier-1", f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if grant.AccessToken != "ghu_access" || grant.RefreshToken != "ghr_refresh" {
		t.Fatalf("grant = %+v", grant)
	}
	if grant.ProviderLogin != "octocat" {
		t.Errorf("login = %q", grant.ProviderLogin)
	}
	if grant.AccessExpiry.IsZero() {
		t.Error("access expiry not set")
	}
	form := f.lastTokenForm
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "code-1" ||
		form.Get("code_verifier") != "verifier-1" || form.Get("client_secret") != "secret" {
		t.Errorf("form = %v", form)
	}
}

func TestGitHubRefresh(t *testing.T) {
	f := newFakeGitHub(t)
	p := f.provider(t)
	grant, err := p.Refresh(context.Background(), "ghr_old", f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if grant.RefreshToken != "ghr_refresh" {
		t.Errorf("rotated = %q", grant.RefreshToken)
	}
	if f.lastTokenForm.Get("grant_type") != "refresh_token" || f.lastTokenForm.Get("refresh_token") != "ghr_old" {
		t.Errorf("form = %v", f.lastTokenForm)
	}
}

func TestGitHubRefreshGrantInvalid(t *testing.T) {
	for _, code := range []string{"bad_refresh_token", "bad_verification_code", "incorrect_client_credentials"} {
		f := newFakeGitHub(t)
		f.tokenErr = code
		p := f.provider(t)
		_, err := p.Refresh(context.Background(), "ghr_old", f.srv.URL)
		if !errors.Is(err, ErrGrantInvalid) {
			t.Errorf("%s: err = %v, want ErrGrantInvalid", code, err)
		}
	}
}

func TestGitHubRefreshTransientError(t *testing.T) {
	f := newFakeGitHub(t)
	f.tokenErr = "temporarily_unavailable"
	p := f.provider(t)
	_, err := p.Refresh(context.Background(), "ghr_old", f.srv.URL)
	if err == nil || errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("err = %v, want retryable non-grant error", err)
	}
	if strings.Contains(err.Error(), "ghr_old") {
		t.Error("error leaks the refresh token")
	}
}

func TestGitHubRevoke(t *testing.T) {
	f := newFakeGitHub(t)
	p := f.provider(t)
	if err := p.Revoke(context.Background(), "ghu_access", f.srv.URL); err != nil {
		t.Fatal(err)
	}
	if !f.revokeCalled {
		t.Fatal("revoke endpoint not called")
	}
	if !strings.HasPrefix(f.revokeAuth, "Basic ") {
		t.Errorf("revoke auth = %q, want basic client auth", f.revokeAuth)
	}
}

func TestGitHubErrorsNeverLeakSecrets(t *testing.T) {
	f := newFakeGitHub(t)
	f.tokenErr = "bad_refresh_token"
	p := f.provider(t)
	_, err := p.Refresh(context.Background(), "ghr_super_secret", f.srv.URL)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "ghr_super_secret") || strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaks secret material: %v", err)
	}
}

func TestGitHubProviderConfigured(t *testing.T) {
	f := newFakeGitHub(t)
	if !f.provider(t).Configured() {
		t.Error("github provider with credentials must report configured")
	}
}

func TestPlannedProviderStubs(t *testing.T) {
	p := PlannedProvider{ProviderName: "gitlab"}
	if p.Name() != "gitlab" {
		t.Fatal(p.Name())
	}
	if p.Configured() {
		t.Error("planned provider must report not configured")
	}
	if _, err := p.AuthorizeURL("s", "c", ""); !errors.Is(err, ErrProviderNotEnabled) {
		t.Errorf("authorize: %v", err)
	}
	if _, err := p.Exchange(context.Background(), "c", "v", ""); !errors.Is(err, ErrProviderNotEnabled) {
		t.Errorf("exchange: %v", err)
	}
	if _, err := p.Refresh(context.Background(), "r", ""); !errors.Is(err, ErrProviderNotEnabled) {
		t.Errorf("refresh: %v", err)
	}
	if err := p.Revoke(context.Background(), "a", ""); !errors.Is(err, ErrProviderNotEnabled) {
		t.Errorf("revoke: %v", err)
	}
}
