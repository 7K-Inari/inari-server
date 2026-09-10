package tenancy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestIdentityClientID(t *testing.T) {
	if got := identityClientID("acme", "ci-bot"); got != "org-acme-ci-bot" {
		t.Errorf("identityClientID = %q, want org-acme-ci-bot", got)
	}
}

// TestSetRBACMappingsRejectsDuplicateTeams guards the tuple-rewrite bug
// where a repeated team emitted multiple changes with the same old role and
// the tuple writer granted every new role. Validation runs before any DB
// access, so a nil-backed service is enough.
func TestSetRBACMappingsRejectsDuplicateTeams(t *testing.T) {
	svc := NewService(nil, nil, nil, nil)
	_, err := svc.SetRBACMappings(context.Background(), "u1", "acme", []types.TeamRoleMapping{
		{Team: "developers", Role: types.RoleViewer},
		{Team: "developers", Role: types.RoleOrgAdmin},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate team") {
		t.Errorf("err = %v, want duplicate team error", err)
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
