//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

// viewerOnly grants tenant.read and nothing else: an org member whose role
// bundle carries no manage permissions (e.g. the built-in viewer role).
// Used to prove the write routes enforce their fine-grained permission slugs
// instead of the coarse "is an org member" gateway check (run d701e2ba B7).
type viewerOnly struct{}

func (viewerOnly) Check(_ context.Context, _, relation, _ string) (bool, error) {
	return relation == authz.RelationTenantRead, nil
}
func (viewerOnly) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func newTenancyHTTPServer(t *testing.T, az authz.Authorizer) *httptest.Server {
	t.Helper()
	database := setupDB(t)
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore())
	if _, _, err := svc.CreateTenant(context.Background(), "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}}, readyOK{})
	tenancy.NewHandler(svc, az).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func rbacReq(t *testing.T, srv *httptest.Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	r, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer good")
	r.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestRBACWriteRoutesForbiddenWithoutManagePermissions is the coded form of
// the live B7 matrix (run d701e2ba): a member whose role bundle lacks the
// manage permissions gets 403 on every RBAC write route, while read routes
// stay available.
func TestRBACWriteRoutesForbiddenWithoutManagePermissions(t *testing.T) {
	srv := newTenancyHTTPServer(t, viewerOnly{})

	// Sanity: the read side of the same surface stays open with tenant.read.
	if code, body := rbacReq(t, srv, http.MethodGet, "/api/v1/tenants/acme/roles", ""); code != http.StatusOK {
		t.Fatalf("GET roles with tenant.read: %d %v, want 200", code, body)
	}

	forbidden := []struct {
		method, path, body string
	}{
		// Role management (tenant.rbac.manage).
		{http.MethodPost, "/api/v1/tenants/acme/roles", `{"name":"x","permissions":["tenant.read"]}`},
		{http.MethodPatch, "/api/v1/tenants/acme/roles/admin", `{"permissions":["tenant.read"]}`},
		{http.MethodDelete, "/api/v1/tenants/acme/roles/viewer", ""},
		{http.MethodPut, "/api/v1/tenants/acme/rbac/mappings", `{"mappings":[{"team":"developers","roleId":"viewer"}]}`},
		// Team management (tenant.teams.manage).
		{http.MethodPost, "/api/v1/tenants/acme/teams", `{"name":"x","roleId":"viewer"}`},
		{http.MethodDelete, "/api/v1/tenants/acme/teams/developers", ""},
		// Member management (tenant.members.manage), including self-promotion.
		{http.MethodPut, "/api/v1/tenants/acme/members/user-1", `{"roleId":"admin"}`},
		{http.MethodDelete, "/api/v1/tenants/acme/members/user-1", ""},
	}
	for _, tc := range forbidden {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			code, body := rbacReq(t, srv, tc.method, tc.path, tc.body)
			if code != http.StatusForbidden {
				t.Fatalf("%s %s: %d %v, want 403", tc.method, tc.path, code, body)
			}
		})
	}
}

// TestAdminGuardrailHTTP covers the guardrail mutation points that only had
// service-level tests: removing the last admin mapping via PUT
// /rbac/mappings and deleting a (custom) team that holds the last admin
// mapping must both surface HTTP 409 (run d701e2ba B6).
func TestAdminGuardrailHTTP(t *testing.T) {
	srv := newTenancyHTTPServer(t, allowAdmin{})

	// PUT /rbac/mappings applies the listed entries as a delta; remapping the
	// only admin-bound team (org-admins) to a non-admin role leaves no team
	// retaining tenant.admin — a guardrail violation.
	code, body := rbacReq(t, srv, http.MethodPut, "/api/v1/tenants/acme/rbac/mappings",
		`{"mappings":[{"team":"org-admins","roleId":"viewer"}]}`)
	if code != http.StatusConflict {
		t.Fatalf("mappings PUT dropping last admin: %d %v, want 409", code, body)
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, "tenant.admin") {
		t.Errorf("mappings PUT 409 detail = %q, want it to name tenant.admin", detail)
	}

	// Give a custom team the admin role, then remap org-admins away from
	// admin — legal now, the custom team retains tenant.admin.
	code, body = rbacReq(t, srv, http.MethodPost, "/api/v1/tenants/acme/teams",
		`{"name":"ops","roleId":"admin"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("create ops team: %d %v", code, body)
	}
	code, body = rbacReq(t, srv, http.MethodPut, "/api/v1/tenants/acme/rbac/mappings",
		`{"mappings":[{"team":"org-admins","roleId":"viewer"}]}`)
	if code != http.StatusOK {
		t.Fatalf("move admin mapping to ops: %d %v, want 200", code, body)
	}

	// Deleting the team that now holds the only admin mapping is a guardrail
	// violation, not a plain delete.
	code, body = rbacReq(t, srv, http.MethodDelete, "/api/v1/tenants/acme/teams/ops", "")
	if code != http.StatusConflict {
		t.Fatalf("delete team holding last admin: %d %v, want 409", code, body)
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, "tenant.admin") {
		t.Errorf("team delete 409 detail = %q, want it to name tenant.admin", detail)
	}

	// The team must still exist (the delete rolled back).
	code, body = rbacReq(t, srv, http.MethodGet, "/api/v1/tenants/acme/teams", "")
	if code != http.StatusOK || !strings.Contains(fmt.Sprint(body), "ops") {
		t.Fatalf("ops team missing after guardrailed delete: %d %v", code, body)
	}
}
