package tenancy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

type stubValidator struct{ id *authn.Identity }

func (s stubValidator) Validate(context.Context, string) (*authn.Identity, error) { return s.id, nil }

type stubReady struct{}

func (stubReady) Ping(context.Context) error { return nil }

type flagAuthorizer struct{ allow bool }

func (f flagAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	if object == authz.ObjectPlatform && relation == authz.RelationOrgCreator {
		return f.allow, nil
	}
	return false, nil
}

func (f flagAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func newMeTestServer(t *testing.T, az authz.Authorizer) *httptest.Server {
	t.Helper()
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)),
		stubValidator{id: &authn.Identity{Subject: "u1"}}, stubReady{})
	NewMeHandler(az, nil).RegisterRoutes(api)
	NewHandler(nil, az).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

type stubTenantResolver struct{ org *types.Organization }

func (s stubTenantResolver) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if s.org != nil && slug == "acme" {
		return s.org, nil
	}
	return nil, ErrOrgNotFound
}

// roleAuthorizer grants relation admin only for subject u1 on org:o1.
type roleAuthorizer struct{}

func (roleAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	return user == authz.UserObject("u1") && relation == authz.RelationAdmin && object == authz.OrgObject("org:o1"), nil
}

func (roleAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func TestMyPermissionsOrgRoles(t *testing.T) {
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)),
		stubValidator{id: &authn.Identity{Subject: "u1", Organizations: []string{"acme"}}}, stubReady{})
	NewMeHandler(roleAuthorizer{}, stubTenantResolver{org: &types.Organization{ID: "org:o1", Slug: "acme"}}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	resp := testTokenReq(t, http.MethodGet, srv.URL+"/api/v1/me/permissions", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body struct {
		OrgRoles map[string]types.Role `json:"orgRoles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.OrgRoles["acme"] != types.RoleOrgAdmin {
		t.Fatalf("orgRoles = %v, want acme=org-admin", body.OrgRoles)
	}
}

func testTokenReq(t *testing.T, method, url, body string) *http.Response {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer good")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestMyPermissionsAllowed(t *testing.T) {
	srv := newMeTestServer(t, flagAuthorizer{allow: true})
	resp := testTokenReq(t, http.MethodGet, srv.URL+"/api/v1/me/permissions", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body struct {
		CanCreateOrganizations bool `json:"canCreateOrganizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.CanCreateOrganizations {
		t.Error("canCreateOrganizations = false, want true")
	}
}

func TestMyPermissionsDenied(t *testing.T) {
	srv := newMeTestServer(t, flagAuthorizer{allow: false})
	resp := testTokenReq(t, http.MethodGet, srv.URL+"/api/v1/me/permissions", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body struct {
		CanCreateOrganizations bool `json:"canCreateOrganizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.CanCreateOrganizations {
		t.Error("canCreateOrganizations = true, want false")
	}
}

func TestMyPermissionsRequiresToken(t *testing.T) {
	srv := newMeTestServer(t, flagAuthorizer{allow: true})
	resp, err := http.Get(srv.URL + "/api/v1/me/permissions")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
}

// multiRoleAuthorizer grants u1 admin on org:o1 (acme), developer on
// org:o2 (beta), platform-engineer on org:o3 (gamma), and viewer on
// org:o4 (delta), mirroring hierarchical FGA relations.
type multiRoleAuthorizer struct{}

func (multiRoleAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	if user != authz.UserObject("u1") {
		return false, nil
	}
	switch object {
	case authz.OrgObject("org:o1"):
		return true, nil // admin implies every relation
	case authz.OrgObject("org:o2"):
		return relation == authz.RelationDeveloper || relation == authz.RelationViewer, nil
	case authz.OrgObject("org:o3"):
		return relation != authz.RelationAdmin, nil // platform-engineer implies developer + viewer
	case authz.OrgObject("org:o4"):
		return relation == authz.RelationViewer, nil
	}
	return false, nil
}

func (multiRoleAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type multiTenantResolver struct {
	orgs map[string]*types.Organization
}

func (s multiTenantResolver) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if org, ok := s.orgs[slug]; ok {
		return org, nil
	}
	return nil, ErrOrgNotFound
}

func TestMyPermissionsTenantCapabilities(t *testing.T) {
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)),
		stubValidator{id: &authn.Identity{Subject: "u1", Organizations: []string{"acme", "beta", "gamma", "delta"}}}, stubReady{})
	NewMeHandler(multiRoleAuthorizer{}, multiTenantResolver{orgs: map[string]*types.Organization{
		"acme":  {ID: "org:o1", Slug: "acme"},
		"beta":  {ID: "org:o2", Slug: "beta"},
		"gamma": {ID: "org:o3", Slug: "gamma"},
		"delta": {ID: "org:o4", Slug: "delta"},
	}}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	resp := testTokenReq(t, http.MethodGet, srv.URL+"/api/v1/me/permissions", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var body struct {
		OrgRoles map[string]types.Role         `json:"orgRoles"`
		Tenants  map[string]TenantCapabilities `json:"tenants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	// Existing fields unchanged.
	if body.OrgRoles["acme"] != types.RoleOrgAdmin || body.OrgRoles["beta"] != types.RoleDeveloper ||
		body.OrgRoles["gamma"] != types.RolePlatformEngineer || body.OrgRoles["delta"] != types.RoleViewer {
		t.Fatalf("orgRoles = %v", body.OrgRoles)
	}
	// Admin gets every capability.
	acme := body.Tenants["acme"]
	if !acme.CanDeploy || !acme.CanManageMembers || !acme.CanManageTeams || !acme.CanManageRbac {
		t.Errorf("acme caps = %+v, want all true", acme)
	}
	// Developer can only deploy.
	beta := body.Tenants["beta"]
	if !beta.CanDeploy || beta.CanManageMembers || beta.CanManageTeams || beta.CanManageRbac {
		t.Errorf("beta caps = %+v, want canDeploy only", beta)
	}
	// Platform-engineer deploys and manages members, but not teams/RBAC.
	gamma := body.Tenants["gamma"]
	if !gamma.CanDeploy || !gamma.CanManageMembers || gamma.CanManageTeams || gamma.CanManageRbac {
		t.Errorf("gamma caps = %+v, want canDeploy+canManageMembers only", gamma)
	}
	// Viewer gets an entry with every capability false.
	delta, ok := body.Tenants["delta"]
	if !ok {
		t.Fatal("tenants missing viewer org delta")
	}
	if delta.CanDeploy || delta.CanManageMembers || delta.CanManageTeams || delta.CanManageRbac {
		t.Errorf("delta caps = %+v, want all false", delta)
	}
}

// A stale org claim (e.g. a deleted tenant still in the token) is skipped
// instead of failing the whole projection.
func TestMyPermissionsSkipsStaleOrgClaim(t *testing.T) {
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)),
		stubValidator{id: &authn.Identity{Subject: "u1", Organizations: []string{"acme", "ghost"}}}, stubReady{})
	NewMeHandler(multiRoleAuthorizer{}, multiTenantResolver{orgs: map[string]*types.Organization{
		"acme": {ID: "org:o1", Slug: "acme"},
	}}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	resp := testTokenReq(t, http.MethodGet, srv.URL+"/api/v1/me/permissions", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200 (stale claim must not fail the request)", resp.StatusCode)
	}
	var body struct {
		OrgRoles map[string]types.Role         `json:"orgRoles"`
		Tenants  map[string]TenantCapabilities `json:"tenants"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.OrgRoles) != 1 || body.OrgRoles["acme"] != types.RoleOrgAdmin {
		t.Errorf("orgRoles = %v, want only acme", body.OrgRoles)
	}
	if _, ok := body.Tenants["ghost"]; ok {
		t.Errorf("tenants must not contain the stale org: %v", body.Tenants)
	}
}

func TestCreateTenantForbiddenWithoutOrgCreator(t *testing.T) {
	srv := newMeTestServer(t, flagAuthorizer{allow: false})
	resp := testTokenReq(t, http.MethodPost, srv.URL+"/api/v1/tenants",
		`{"slug":"acme","displayName":"Acme"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
	var body struct {
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.Detail, "org_creator") {
		t.Errorf("detail = %q, want org_creator mention", body.Detail)
	}
}
