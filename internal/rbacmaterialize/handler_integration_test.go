//go:build integration

package rbacmaterialize_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/rbacmaterialize"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

func itDB(t *testing.T) *db.DB {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("inari"),
		postgres.WithUsername("inari"),
		postgres.WithPassword("inari"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return database
}

// fakeIdP satisfies tenancy.IdentityProvider for tenant/team lifecycle
// calls that write Keycloak state.
type fakeIdP struct{ next int }

func (f *fakeIdP) CreateOrganization(context.Context, string, string) (string, error) {
	f.next++
	return fmt.Sprintf("kc-%d", f.next), nil
}
func (f *fakeIdP) UpdateOrganization(context.Context, string, string) error { return nil }
func (f *fakeIdP) DeleteOrganization(context.Context, string) error         { return nil }
func (f *fakeIdP) CreateGroup(_ context.Context, path string) (string, error) {
	return "grp-" + path, nil
}
func (f *fakeIdP) DeleteGroup(context.Context, string) error                      { return nil }
func (f *fakeIdP) ListOrganizations(context.Context, string) ([]string, error)    { return nil, nil }
func (f *fakeIdP) AddOrganizationMember(context.Context, string, string) error    { return nil }
func (f *fakeIdP) RemoveOrganizationMember(context.Context, string, string) error { return nil }
func (f *fakeIdP) AddGroupMember(context.Context, string, string) error           { return nil }
func (f *fakeIdP) RemoveGroupMember(context.Context, string, string) error        { return nil }
func (f *fakeIdP) ListGroupMembers(context.Context, string) ([]string, error)     { return nil, nil }
func (f *fakeIdP) GetUser(context.Context, string) (*types.User, error)           { return nil, nil }

func setup(t *testing.T) (*db.DB, *tenancy.Service, *gitprovider.Fake, *audit.Dispatcher, context.Context) {
	t.Helper()
	database := itDB(t)
	ctx := context.Background()
	svc := tenancy.NewService(database, &fakeIdP{}, tenancy.NewStore(), audit.NewStore())
	git := gitprovider.NewFake()
	h := rbacmaterialize.NewHandler(svc,
		rbacmaterialize.NewInventoryGitConfigs(database, inventory.NewStore()), git, nil)
	disp := audit.NewDispatcher(database, 10*time.Millisecond, h)
	return database, svc, git, disp, ctx
}

func TestMaterializesOnTenantAndMappingLifecycle(t *testing.T) {
	_, svc, git, disp, ctx := setup(t)

	_, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(teams) == 0 {
		t.Fatal("expected seeded default teams")
	}
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}

	files := git.Files("acme-inari-state", "main")
	roles, ok := files[rbacmaterialize.ClusterRolesPath]
	if !ok {
		t.Fatalf("cluster roles not committed: %v", files)
	}
	for _, name := range []string{"tenant-acme-admin", "tenant-acme-operator", "tenant-acme-editor", "tenant-acme-viewer"} {
		if !strings.Contains(roles, "name: "+name) {
			t.Errorf("anchor role %s missing from committed manifest", name)
		}
	}
	bindings := files[rbacmaterialize.ClusterRoleBindingsPath]
	if !strings.Contains(bindings, "/tenant-acme/") {
		t.Errorf("bindings lack group subjects: %s", bindings)
	}
	if _, ok := files[rbacmaterialize.RootAppPath]; !ok {
		t.Error("root app not seeded for repo created outside the zone flow")
	}

	// A mapping change must flip the affected binding's roleRef.
	team := teams[0]
	newRole := types.RoleViewer
	if team.Role == newRole {
		newRole = types.RoleOrgAdmin
	}
	if _, err := svc.SetRBACMappings(ctx, "user-1", "acme",
		[]types.TeamRoleMapping{{Team: team.Name, Role: newRole}}); err != nil {
		t.Fatal(err)
	}
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	updated := git.Files("acme-inari-state", "main")[rbacmaterialize.ClusterRoleBindingsPath]
	wantRef, _ := rbacmaterialize.ClusterRoleName("acme", newRole)
	if !strings.Contains(updated, "name: "+wantRef) {
		t.Errorf("binding roleRef not updated to %s:\n%s", wantRef, updated)
	}

	// Idempotency: redispatching with no changes must not alter content.
	before := git.Files("acme-inari-state", "main")
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	after := git.Files("acme-inari-state", "main")
	for p, c := range before {
		if after[p] != c {
			t.Errorf("content drift at %s without any change", p)
		}
	}
}
func TestMaterializesTeamDelete(t *testing.T) {
	_, svc, git, disp, ctx := setup(t)

	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	extra, err := svc.CreateTeam(ctx, "user-1", "acme", "temp", types.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	bindings := git.Files("acme-inari-state", "main")[rbacmaterialize.ClusterRoleBindingsPath]
	if !strings.Contains(bindings, "tenant-acme-temp") {
		t.Fatalf("team binding not committed: %s", bindings)
	}

	if err := svc.DeleteTeam(ctx, "user-1", "acme", extra.Name); err != nil {
		t.Fatal(err)
	}
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	bindings = git.Files("acme-inari-state", "main")[rbacmaterialize.ClusterRoleBindingsPath]
	if strings.Contains(bindings, "tenant-acme-temp") {
		t.Errorf("deleted team binding still present: %s", bindings)
	}
}
