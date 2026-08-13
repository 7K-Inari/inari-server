package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
)

type stubValidator struct {
	id  *authn.Identity
	err error
}

func (s stubValidator) Validate(context.Context, string) (*authn.Identity, error) {
	return s.id, s.err
}

type stubReady struct{ err error }

func (s stubReady) Ping(context.Context) error { return s.err }

func newTestServer(t *testing.T, v authn.Validator, ready ReadinessChecker) *httptest.Server {
	t.Helper()
	router, api := NewRouter(slog.New(slog.NewTextHandler(nil, nil)), v, ready)
	huma.Register(api, huma.Operation{
		OperationID: "whoami",
		Method:      http.MethodGet,
		Path:        "/api/v1/whoami",
		Security:    SecurityRequirement(),
	}, func(ctx context.Context, _ *struct{}) (*struct{ Body struct{ Sub string `json:"sub"` } }, error) {
		id := IdentityFromContext(ctx)
		if id == nil {
			return nil, huma.Error401Unauthorized("unauthenticated")
		}
		out := &struct{ Body struct{ Sub string `json:"sub"` } }{}
		out.Body.Sub = id.Subject
		return out, nil
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func TestHealthzNoAuth(t *testing.T) {
	srv := newTestServer(t, stubValidator{err: errors.New("nope")}, stubReady{})
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: got %d", resp.StatusCode)
	}
}

func TestReadyzFailsWhenDependencyDown(t *testing.T) {
	srv := newTestServer(t, stubValidator{}, stubReady{err: errors.New("db down")})
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz: got %d, want 503", resp.StatusCode)
	}
}

func TestSecuredRouteRejectsMissingToken(t *testing.T) {
	srv := newTestServer(t, stubValidator{id: &authn.Identity{Subject: "u1"}}, stubReady{})
	resp, err := http.Get(srv.URL + "/api/v1/whoami")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
}

func TestSecuredRouteRejectsInvalidToken(t *testing.T) {
	srv := newTestServer(t, stubValidator{err: errors.New("bad token")}, stubReady{})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
}

func TestSecuredRouteAcceptsValidToken(t *testing.T) {
	srv := newTestServer(t, stubValidator{id: &authn.Identity{Subject: "u1"}}, stubReady{})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer good")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body struct {
		Sub string `json:"sub"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Sub != "u1" {
		t.Fatalf("sub = %q, want u1", body.Sub)
	}
}

// TestBearerSchemeIsEnforced documents that a non-Bearer scheme must not
// authenticate even when the remainder is a valid token.
func TestBearerSchemeIsEnforced(t *testing.T) {
	srv := newTestServer(t, stubValidator{id: &authn.Identity{Subject: "u1"}}, stubReady{})
	for _, hdr := range []string{"BearerXgood", "Token good", "Basic good!"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/whoami", nil)
		req.Header.Set("Authorization", hdr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("header %q: got %d, want 401", hdr, resp.StatusCode)
		}
	}
}
