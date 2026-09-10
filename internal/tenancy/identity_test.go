package tenancy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
)

func TestIdentityClientID(t *testing.T) {
	if got := identityClientID("acme", "ci-bot"); got != "org-acme-ci-bot" {
		t.Errorf("identityClientID = %q, want org-acme-ci-bot", got)
	}
}

// TestIdentityRoutesRequireOrgMembership verifies the coarse PEP: without the
// org claim every identity/RBAC route is 403 before any service call (the
// handler is constructed with a nil service, so reaching it would panic).
func TestIdentityRoutesRequireOrgMembership(t *testing.T) {
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		stubValidator{id: &authn.Identity{Subject: "u1"}}, stubReady{})
	NewHandler(nil, flagAuthorizer{allow: true}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/v1/tenants/acme/identity/clients", ""},
		{http.MethodPost, "/api/v1/tenants/acme/identity/clients", `{"name":"foo","type":"service"}`},
		{http.MethodGet, "/api/v1/tenants/acme/identity/clients/org-acme-foo", ""},
		{http.MethodPatch, "/api/v1/tenants/acme/identity/clients/org-acme-foo", "{}"},
		{http.MethodDelete, "/api/v1/tenants/acme/identity/clients/org-acme-foo", ""},
		{http.MethodPut, "/api/v1/tenants/acme/identity/clients/org-acme-foo/scopes", `{"scopes":["read"]}`},
		{http.MethodPost, "/api/v1/tenants/acme/identity/clients/org-acme-foo/secret:rotate", "{}"},
		{http.MethodGet, "/api/v1/tenants/acme/identity/scopes", ""},
		{http.MethodPut, "/api/v1/tenants/acme/rbac/mappings", `{"mappings":[{"team":"developers","role":"viewer"}]}`},
	} {
		resp := testTokenReq(t, tc.method, srv.URL+tc.path, tc.body)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", tc.method, tc.path, resp.StatusCode)
		}
	}
}
