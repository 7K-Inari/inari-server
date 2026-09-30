//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/eventbus/eventbustest"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

func setupRolesTenant(t *testing.T) (context.Context, *tenancy.Service, *types.Organization) {
	t.Helper()
	database := setupDB(t)
	ctx := context.Background()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	return ctx, svc, org
}

func TestCreateTenantSeedsBuiltinRoles(t *testing.T) {
	ctx, svc, org := setupRolesTenant(t)
	roles, err := svc.ListRoles(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 4 {
		t.Fatalf("seeded roles = %d, want 4", len(roles))
	}
	byName := map[string]types.Role{}
	for _, r := range roles {
		byName[r.Name] = r
		if !r.Builtin {
			t.Errorf("seeded role %q not marked builtin", r.Name)
		}
	}
	if got := byName["admin"].Permissions; len(got) != len(authz.PermissionCatalog()) {
		t.Errorf("admin bundle = %d permissions, want %d", len(got), len(authz.PermissionCatalog()))
	}
	if got := byName["viewer"].Permissions; len(got) != 1 || got[0] != "tenant.read" {
		t.Errorf("viewer bundle = %v", got)
	}
	if !slices.Contains(byName["operator"].Permissions, "clusters.register") ||
		slices.Contains(byName["operator"].Permissions, "tenant.admin") {
		t.Errorf("operator bundle wrong: %v", byName["operator"].Permissions)
	}
	// Default teams are bound to their role FKs with joined names.
	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tm := range teams {
		if tm.RoleID == "" || tm.RoleName == "" {
			t.Errorf("team %q missing role binding: %+v", tm.Name, tm)
		}
	}
}

func TestRoleCRUDAndValidation(t *testing.T) {
	ctx, svc, org := setupRolesTenant(t)

	// Validation: bad name, unknown permission, duplicate slug.
	if _, err := svc.CreateRole(ctx, "user-1", "acme", &types.Role{Name: "Bad_Name", Permissions: []string{"tenant.read"}}); err == nil {
		t.Error("DNS-1123 violation accepted")
	}
	if _, err := svc.CreateRole(ctx, "user-1", "acme", &types.Role{Name: "x", Permissions: []string{"bogus.slug"}}); err == nil {
		t.Error("unknown permission accepted")
	}
	if _, err := svc.CreateRole(ctx, "user-1", "acme", &types.Role{Name: "x", Permissions: []string{"tenant.read", "tenant.read"}}); err == nil {
		t.Error("duplicate permission accepted")
	}

	role, err := svc.CreateRole(ctx, "user-1", "acme", &types.Role{
		Name: "deployer", DisplayName: "Deployer", Permissions: []string{"deployments.create", "tenant.read"},
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if role.ID == "" || role.Builtin {
		t.Errorf("created role = %+v", role)
	}
	if _, err := svc.CreateRole(ctx, "user-1", "acme", &types.Role{Name: "deployer", Permissions: []string{"tenant.read"}}); !errors.Is(err, tenancy.ErrRoleNameTaken) {
		t.Errorf("duplicate name: err = %v, want ErrRoleNameTaken", err)
	}

	// GetRole by name and by ID.
	if _, err := svc.GetRole(ctx, "acme", "deployer"); err != nil {
		t.Errorf("GetRole by name: %v", err)
	}
	if _, err := svc.GetRole(ctx, "acme", role.ID); err != nil {
		t.Errorf("GetRole by ID: %v", err)
	}

	// Rename a custom role; builtin rename is rejected.
	updated, err := svc.UpdateRole(ctx, "user-1", "acme", "deployer", tenancy.RolePatch{
		Name: ptr("releaser"), Description: ptr("ships things"),
	})
	if err != nil {
		t.Fatalf("UpdateRole rename: %v", err)
	}
	if updated.Name != "releaser" || updated.Description != "ships things" {
		t.Errorf("updated = %+v", updated)
	}
	if _, err := svc.UpdateRole(ctx, "user-1", "acme", "admin", tenancy.RolePatch{Name: ptr("root")}); !errors.Is(err, tenancy.ErrBuiltinRole) {
		t.Errorf("builtin rename: err = %v, want ErrBuiltinRole", err)
	}

	// Built-in permissions are editable (bundle swap, guardrail intact:
	// org-admins stays bound and keeps tenant.admin).
	if _, err := svc.UpdateRole(ctx, "user-1", "acme", "editor", tenancy.RolePatch{
		Permissions: &[]string{"tenant.read", "catalog.manage"},
	}); err != nil {
		t.Errorf("builtin permission edit: %v", err)
	}

	// Delete: builtin rejected; unbound custom deleted.
	if err := svc.DeleteRole(ctx, "user-1", "acme", "viewer"); !errors.Is(err, tenancy.ErrBuiltinRole) {
		t.Errorf("builtin delete: err = %v, want ErrBuiltinRole", err)
	}
	if err := svc.DeleteRole(ctx, "user-1", "acme", "releaser"); err != nil {
		t.Errorf("DeleteRole: %v", err)
	}
	if _, err := svc.GetRole(ctx, "acme", "releaser"); !errors.Is(err, tenancy.ErrRoleNotFound) {
		t.Errorf("deleted role still resolves: %v", err)
	}
	_ = org
}

func TestRoleDeleteInUseRejected(t *testing.T) {
	ctx, svc, _ := setupRolesTenant(t)
	role, err := svc.CreateRole(ctx, "user-1", "acme", &types.Role{Name: "deployer", Permissions: []string{"deployments.create"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTeam(ctx, "user-1", "acme", "release", role.ID); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if err := svc.DeleteRole(ctx, "user-1", "acme", "deployer"); !errors.Is(err, tenancy.ErrRoleInUse) {
		t.Errorf("delete in use: err = %v, want ErrRoleInUse", err)
	}
	// Unmapping the team frees the role.
	if _, err := svc.SetRBACMappings(ctx, "user-1", "acme", []types.TeamRoleMapping{
		{Team: "release", RoleID: "viewer"},
	}); err != nil {
		t.Fatalf("SetRBACMappings: %v", err)
	}
	if err := svc.DeleteRole(ctx, "user-1", "acme", "deployer"); err != nil {
		t.Errorf("DeleteRole after unmap: %v", err)
	}
}

// TestAdminGuardrail pins the lockout protection at every mutation point:
// role PATCH, rbac/mappings PUT, and team delete (ADR-0013).
func TestAdminGuardrail(t *testing.T) {
	ctx, svc, _ := setupRolesTenant(t)
	admin, err := svc.GetRole(ctx, "acme", "admin")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := svc.GetRole(ctx, "acme", "operator")
	if err != nil {
		t.Fatal(err)
	}

	// PATCH stripping tenant.admin from the only admin-granting role.
	without := make([]string, 0, len(admin.Permissions))
	for _, p := range admin.Permissions {
		if p != "tenant.admin" {
			without = append(without, p)
		}
	}
	if _, err := svc.UpdateRole(ctx, "user-1", "acme", "admin", tenancy.RolePatch{Permissions: &without}); !errors.Is(err, tenancy.ErrAdminGuardrail) {
		t.Errorf("PATCH violating guardrail: err = %v, want ErrAdminGuardrail", err)
	}
	// The failed PATCH rolled back.
	still, err := svc.GetRole(ctx, "acme", "admin")
	if err != nil || !slices.Contains(still.Permissions, "tenant.admin") {
		t.Errorf("admin bundle changed despite rollback: %v err=%v", still, err)
	}

	// Mappings flipping the last admin team away.
	if _, err := svc.SetRBACMappings(ctx, "user-1", "acme", []types.TeamRoleMapping{
		{Team: "org-admins", RoleID: operator.ID},
	}); !errors.Is(err, tenancy.ErrAdminGuardrail) {
		t.Errorf("mappings violating guardrail: err = %v, want ErrAdminGuardrail", err)
	}

	// A second admin-bearing team lifts the guardrail for both operations.
	if _, err := svc.SetRBACMappings(ctx, "user-1", "acme", []types.TeamRoleMapping{
		{Team: "viewers", RoleID: admin.ID},
	}); err != nil {
		t.Fatalf("add second admin team: %v", err)
	}
	if _, err := svc.SetRBACMappings(ctx, "user-1", "acme", []types.TeamRoleMapping{
		{Team: "org-admins", RoleID: operator.ID},
	}); err != nil {
		t.Errorf("flip allowed with another admin team present: %v", err)
	}

	// Team delete violating the guardrail: make a custom team the last
	// admin-bearing team (the built-in anchors are delete-protected for a
	// different reason), then delete it.
	if _, err := svc.CreateTeam(ctx, "user-1", "acme", "backup-admins", admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetRBACMappings(ctx, "user-1", "acme", []types.TeamRoleMapping{
		{Team: "viewers", RoleID: "viewer"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteTeam(ctx, "user-1", "acme", "backup-admins"); !errors.Is(err, tenancy.ErrAdminGuardrail) {
		t.Errorf("team delete violating guardrail: err = %v, want ErrAdminGuardrail", err)
	}
	// The failed delete rolled back: backup-admins still exists.
	if _, err := svc.CreateTeam(ctx, "user-1", "acme", "backup-admins", admin.ID); !errors.Is(err, tenancy.ErrTeamNameTaken) {
		t.Errorf("backup-admins gone despite rollback: err = %v", err)
	}
}

// TestAdminGuardrailConcurrentStrip interleaves two transactions that each
// strip tenant.admin from a different admin-bearing role, following
// Service.UpdateRole's exact TX sequence (lock org, update role, check
// guardrail). Without per-org serialization both guardrail checks pass
// under READ COMMITTED and the tenant locks itself out (QA finding); with
// the organizations-row lock the second transaction blocks until the first
// commits and its guardrail check must fail.
func TestAdminGuardrailConcurrentStrip(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := svc.GetRole(ctx, "acme", "admin")
	if err != nil {
		t.Fatal(err)
	}
	admin2, err := svc.CreateRole(ctx, "user-1", "acme", &types.Role{
		Name: "admin2", Permissions: []string{"tenant.admin", "tenant.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTeam(ctx, "user-1", "acme", "backup-admins", admin2.ID); err != nil {
		t.Fatal(err)
	}
	strip := func(perms []string) []string {
		out := slices.Clone(perms)
		return slices.DeleteFunc(out, func(p string) bool { return p == "tenant.admin" })
	}
	store := tenancy.NewStore()

	// TX1 (main goroutine): lock, strip admin, guardrail check, then pause
	// before commit so TX2 starts its lock attempt while TX1 is open.
	tx1, err := database.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()
	if err := store.LockOrgForGuardrail(ctx, tx1, org.ID); err != nil {
		t.Fatal(err)
	}
	r1 := *admin
	r1.Permissions = strip(admin.Permissions)
	if _, err := store.UpdateRole(ctx, tx1, &r1); err != nil {
		t.Fatal(err)
	}
	ok1, err := store.AdminGuardrailHolds(ctx, tx1, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok1 {
		t.Fatal("tx1 guardrail should hold (admin2 still bears tenant.admin)")
	}

	// TX2 (goroutine): the same sequence. Its LockOrgForGuardrail must
	// block until TX1 commits, then its guardrail check must fail.
	tx2Guardrail := make(chan bool, 1)
	tx2Err := make(chan error, 1)
	tx2Started := make(chan struct{})
	go func() {
		tx2, err := database.Pool.Begin(ctx)
		if err != nil {
			tx2Err <- err
			return
		}
		defer func() { _ = tx2.Rollback(ctx) }()
		close(tx2Started)
		if err := store.LockOrgForGuardrail(ctx, tx2, org.ID); err != nil {
			tx2Err <- err
			return
		}
		r2 := *admin2
		r2.Permissions = strip(admin2.Permissions)
		if _, err := store.UpdateRole(ctx, tx2, &r2); err != nil {
			tx2Err <- err
			return
		}
		ok, err := store.AdminGuardrailHolds(ctx, tx2, org.ID)
		if err != nil {
			tx2Err <- err
			return
		}
		tx2Guardrail <- ok
	}()
	<-tx2Started
	// Give TX2 a moment to reach its (blocking) lock attempt, then commit
	// TX1 — releasing the org lock so TX2 can proceed.
	time.Sleep(200 * time.Millisecond)
	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-tx2Err:
		t.Fatalf("tx2: %v", err)
	case ok2 := <-tx2Guardrail:
		if ok2 {
			t.Fatal("GUARDRAIL RACE: both transactions passed the guardrail check; tenant left with no tenant.admin team")
		}
	}
}

// TestRoleUpdateTupleRewrite dispatches a role.updated event and asserts the
// bound teams' tuples are rewritten from the payload snapshots.
func TestRoleUpdateTupleRewrite(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingStore{}
	disp := eventbustest.Dispatcher(t, database, 50*time.Millisecond, audit.Named("authz-tuple-writer", authz.NewTupleWriter(rec)))
	// Drain tenant.created.
	if err := eventbustest.DispatchOnce(ctx, disp); err != nil {
		t.Fatal(err)
	}
	rec.written, rec.deleted = nil, nil

	// Grant the viewer role deployments.create: the viewers team's tuples
	// must be rewritten.
	newPerms := []string{"tenant.read", "deployments.create"}
	if _, err := svc.UpdateRole(ctx, "user-1", "acme", "viewer", tenancy.RolePatch{Permissions: &newPerms}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if err := eventbustest.DispatchOnce(ctx, disp); err != nil {
		t.Fatal(err)
	}
	var viewersTeamID string
	teams, _ := svc.ListTeams(ctx, org.ID)
	for _, tm := range teams {
		if tm.Name == "viewers" {
			viewersTeamID = tm.ID
		}
	}
	var delRead, addDeploy bool
	for _, tp := range rec.deleted {
		if tp.User == "team:"+viewersTeamID+"#member" && tp.Relation == "tenant_read" {
			delRead = true
		}
	}
	for _, tp := range rec.written {
		if tp.User == "team:"+viewersTeamID+"#member" && tp.Relation == "deployments_create" {
			addDeploy = true
		}
	}
	if !delRead || !addDeploy {
		t.Errorf("role.updated tuple rewrite: deleted=%v written=%v", rec.deleted, rec.written)
	}
	_ = org
}

func TestHasPermissionAndRoleNames(t *testing.T) {
	ctx, svc, org := setupRolesTenant(t)
	// Creator holds admin + operator via the anchor teams.
	ok, err := svc.HasPermission(ctx, org.ID, "user-1", "tenant.admin")
	if err != nil || !ok {
		t.Errorf("creator tenant.admin = %v, %v", ok, err)
	}
	ok, err = svc.HasPermission(ctx, org.ID, "user-1", "clusters.register")
	if err != nil || !ok {
		t.Errorf("creator clusters.register = %v, %v", ok, err)
	}
	ok, err = svc.HasPermission(ctx, org.ID, "ghost", "tenant.read")
	if err != nil || ok {
		t.Errorf("ghost tenant.read = %v, %v", ok, err)
	}
	names, err := svc.ListMemberRoleNames(ctx, org.ID, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, "admin") || !slices.Contains(names, "operator") {
		t.Errorf("creator role names = %v, want admin+operator", names)
	}
}

// TestRoleHTTPRoutes exercises the roles REST surface end-to-end: CRUD,
// the permission catalog, and the 409 mappings (builtin, in-use,
// guardrail).
func TestRoleHTTPRoutes(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	svc := tenancy.NewService(database, newFakeIdP(), tenancy.NewStore(), audit.NewStore())
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		fixedValidator{id: &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}}, readyOK{})
	tenancy.NewHandler(svc, allowAdmin{}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	req := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		var rdr *strings.Reader
		rdr = strings.NewReader(body)
		r, err := http.NewRequest(method, srv.URL+path, rdr)
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

	// Catalog is served.
	code, body := req(http.MethodGet, "/api/v1/tenants/acme/permissions/catalog", "")
	if code != http.StatusOK {
		t.Fatalf("catalog: %d %v", code, body)
	}
	if perms, _ := body["permissions"].([]any); len(perms) != 19 {
		t.Errorf("catalog entries = %d, want 19", len(perms))
	}

	// Built-ins are listed; create + get a custom role.
	code, body = req(http.MethodGet, "/api/v1/tenants/acme/roles", "")
	if code != http.StatusOK || len(body["roles"].([]any)) != 4 {
		t.Fatalf("list roles: %d %v", code, body)
	}
	code, body = req(http.MethodPost, "/api/v1/tenants/acme/roles",
		`{"name":"deployer","permissions":["deployments.create","tenant.read"]}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("create role: %d %v", code, body)
	}
	code, body = req(http.MethodGet, "/api/v1/tenants/acme/roles/deployer", "")
	if code != http.StatusOK {
		t.Fatalf("get role: %d %v", code, body)
	}

	// 409s: builtin rename, builtin delete, guardrail-violating PATCH.
	code, _ = req(http.MethodPatch, "/api/v1/tenants/acme/roles/admin", `{"name":"root"}`)
	if code != http.StatusConflict {
		t.Errorf("builtin rename: %d, want 409", code)
	}
	code, _ = req(http.MethodDelete, "/api/v1/tenants/acme/roles/admin", "")
	if code != http.StatusConflict {
		t.Errorf("builtin delete: %d, want 409", code)
	}
	code, _ = req(http.MethodPatch, "/api/v1/tenants/acme/roles/admin", `{"permissions":["tenant.read"]}`)
	if code != http.StatusConflict {
		t.Errorf("guardrail PATCH: %d, want 409", code)
	}
	// Unknown role: 404; unknown permission slug: 400.
	code, _ = req(http.MethodGet, "/api/v1/tenants/acme/roles/ghost", "")
	if code != http.StatusNotFound {
		t.Errorf("ghost role: %d, want 404", code)
	}
	code, _ = req(http.MethodPost, "/api/v1/tenants/acme/roles", `{"name":"x","permissions":["bogus.slug"]}`)
	if code != http.StatusBadRequest {
		t.Errorf("unknown permission: %d, want 400", code)
	}

	// Delete the custom role.
	code, _ = req(http.MethodDelete, "/api/v1/tenants/acme/roles/deployer", "")
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Errorf("delete custom role: %d", code)
	}
}

func ptr[T any](v T) *T { return &v }
