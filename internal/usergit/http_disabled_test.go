package usergit_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
	"github.com/7K-Inari/inari-server/internal/usergit"
)

type disabledValidator struct{}

func (disabledValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	if raw == "good" {
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}, nil
	}
	return nil, errors.New("invalid token")
}

type disabledAuthorizer struct{}

func (disabledAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (disabledAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type disabledTenants struct{}

func (disabledTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if slug == "acme" {
		return &types.Organization{ID: "org:1", Slug: "acme"}, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

// The module is fail-open when disabled (no KEK / flag off): main wires a
// nil *Service. Every route must answer 501, never panic.
func TestDisabledModuleReturns501(t *testing.T) {
	router, api := httpserver.NewRouter(slog.Default(), disabledValidator{}, nil)
	usergit.NewHandler(nil, disabledTenants{}, disabledAuthorizer{}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()

	paths := []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/v1/tenants/acme/git-connections", ""},
		{http.MethodPost, "/api/v1/tenants/acme/git-connections/github/authorize", "{}"},
		{http.MethodGet, "/api/v1/tenants/acme/git-connections/github/callback?code=x&state=y", ""},
		{http.MethodDelete, "/api/v1/tenants/acme/git-connections/github", ""},
	}
	for _, p := range paths {
		req, err := http.NewRequest(p.method, srv.URL+p.path, strings.NewReader(p.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("%s %s: got %d, want 501", p.method, p.path, resp.StatusCode)
		}
	}
}
