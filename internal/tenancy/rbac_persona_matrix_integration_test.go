//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
)

// personaAuthorizer simulates one org member holding one built-in role: it
// grants exactly the FGA relations of that role's seeded permission bundle
// (authz.BuiltinRolePermissions → PermissionRelation), so the matrix below
// tracks the catalog instead of a hand-copied relation list.
type personaAuthorizer struct {
	subject string
	allowed map[string]bool
}

func authorizerForBuiltinRole(subject, role string) personaAuthorizer {
	allowed := map[string]bool{}
	for _, slug := range authz.BuiltinRolePermissions(role) {
		rel, ok := authz.PermissionRelation(slug)
		if !ok {
			panic("catalog drift: unknown slug " + slug)
		}
		allowed[rel] = true
	}
	return personaAuthorizer{subject: subject, allowed: allowed}
}

func (p personaAuthorizer) Check(_ context.Context, user, relation, _ string) (bool, error) {
	return user == authz.UserObject(p.subject) && p.allowed[relation], nil
}
func (p personaAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

var builtinPersonas = []string{
	authz.BuiltinRoleAdmin,
	authz.BuiltinRoleOperator,
	authz.BuiltinRoleEditor,
	authz.BuiltinRoleViewer,
}

func allowed(codes ...int) map[string][]int {
	return map[string][]int{
		authz.BuiltinRoleAdmin:    codes,
		authz.BuiltinRoleOperator: codes,
		authz.BuiltinRoleEditor:   codes,
		authz.BuiltinRoleViewer:   codes,
	}
}

func adminOnly(codes ...int) map[string][]int {
	return map[string][]int{authz.BuiltinRoleAdmin: codes}
}

func adminAndOperator(codes ...int) map[string][]int {
	return map[string][]int{
		authz.BuiltinRoleAdmin:    codes,
		authz.BuiltinRoleOperator: codes,
	}
}

func containsCode(haystack []int, code int) bool {
	for _, c := range haystack {
		if c == code {
			return true
		}
	}
	return false
}

// TestBuiltinRoleAccessMatrix asserts the PEP outcome of every RBAC-relevant
// tenancy route for four users, one per built-in role (admin, operator,
// editor, viewer). Each persona runs against its own freshly seeded tenant,
// so mutating probes cannot interfere with each other. The matrix is the
// coded form of "multiple users, each with a different default role" access
// control verification (follow-up to run d701e2ba B7).
func TestBuiltinRoleAccessMatrix(t *testing.T) {
	adminPerms, err := json.Marshal(authz.BuiltinRolePermissions(authz.BuiltinRoleAdmin))
	if err != nil {
		t.Fatal(err)
	}

	probes := []struct {
		name   string
		method string
		path   string
		body   string
		want   map[string][]int // role → acceptable statuses; missing role = 403
	}{
		// Reads (tenant.read): every built-in role carries it.
		{"list roles", http.MethodGet, "/api/v1/tenants/acme/roles", "", allowed(http.StatusOK)},
		{"permission catalog", http.MethodGet, "/api/v1/tenants/acme/permissions/catalog", "", allowed(http.StatusOK)},
		{"list teams", http.MethodGet, "/api/v1/tenants/acme/teams", "", allowed(http.StatusOK)},
		{"list org members", http.MethodGet, "/api/v1/tenants/acme/members", "", allowed(http.StatusOK)},
		{"rbac matrix", http.MethodGet, "/api/v1/tenants/acme/rbac", "", allowed(http.StatusOK)},

		// tenant.settings.write: admin only.
		{"update tenant profile", http.MethodPatch, "/api/v1/tenants/acme",
			`{"displayName":"Acme X"}`, adminOnly(http.StatusOK)},

		// tenant.rbac.manage: admin only.
		{"create role", http.MethodPost, "/api/v1/tenants/acme/roles",
			`{"name":"probe","permissions":["tenant.read"]}`, adminOnly(http.StatusOK, http.StatusCreated)},
		{"patch admin role identity-perms", http.MethodPatch, "/api/v1/tenants/acme/roles/admin",
			`{"permissions":` + string(adminPerms) + `}`, adminOnly(http.StatusOK)},
		{"delete custom role", http.MethodDelete, "/api/v1/tenants/acme/roles/probe", "",
			adminOnly(http.StatusOK, http.StatusNoContent)},
		{"put rbac mappings empty delta", http.MethodPut, "/api/v1/tenants/acme/rbac/mappings",
			`{"mappings":[]}`, adminOnly(http.StatusOK)},

		// tenant.teams.manage: admin only (operator deliberately lacks it).
		{"create team", http.MethodPost, "/api/v1/tenants/acme/teams",
			`{"name":"probe","roleId":"viewer"}`, adminOnly(http.StatusOK, http.StatusCreated)},
		// Anchor-team delete is 409 for the allowed persona (default-team
		// protection surfaces only after the PEP passes), 403 for the rest.
		{"delete anchor team", http.MethodDelete, "/api/v1/tenants/acme/teams/viewers", "",
			adminOnly(http.StatusConflict)},

		// setMemberRole gates on tenant.rbac.manage (admin only); probe-user
		// is registered in the fake IdP by newPersonaServer.
		{"set member role", http.MethodPut, "/api/v1/tenants/acme/members/probe-user",
			`{"roleId":"viewer"}`, adminOnly(http.StatusOK, http.StatusNoContent)},
		// removeOrgMember gates on tenant.members.manage (admin + operator).
		// The ghost target exercises the PEP boundary only: for allowed
		// personas the request passes the gate and fails (or idempotently
		// succeeds) in the service, never with 403.
		{"remove org member (ghost)", http.MethodDelete, "/api/v1/tenants/acme/members/ghost-user", "",
			adminAndOperator(http.StatusOK, http.StatusNoContent, http.StatusNotFound)},
	}

	for _, role := range builtinPersonas {
		role := role
		t.Run(role, func(t *testing.T) {
			subject := "user-" + role
			srv := newPersonaServer(t, subject, authorizerForBuiltinRole(subject, role))
			for _, p := range probes {
				p := p
				t.Run(p.name, func(t *testing.T) {
					want, ok := p.want[role]
					if !ok {
						want = []int{http.StatusForbidden}
					}
					code, body := rbacReq(t, srv, p.method, p.path, p.body)
					if !containsCode(want, code) {
						t.Fatalf("%s as %s: %s %s = %d %v, want %v",
							p.name, role, p.method, p.path, code, body, want)
					}
				})
			}
		})
	}
}

// newPersonaServer boots a tenancy HTTP server with one org (acme) and a
// single-member token for the given subject, authorized by az.
func newPersonaServer(t *testing.T, subject string, az authz.Authorizer) *httptest.Server {
	t.Helper()
	database := setupDB(t)
	idp := newFakeIdP()
	idp.users["probe-user"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	if _, _, err := svc.CreateTenant(context.Background(), "user-admin", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: subject, Organizations: []string{"acme"}}}, readyOK{})
	tenancy.NewHandler(svc, az).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}
