//go:build integration

package tenancy_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeIdP struct {
	orgs       map[string]string
	groups     []string
	orgMembers map[string][]string
	grpMembers map[string][]string
	users      map[string]bool
	nextID     int
}

func newFakeIdP() *fakeIdP {
	return &fakeIdP{
		orgs:       map[string]string{},
		orgMembers: map[string][]string{},
		grpMembers: map[string][]string{},
		users:      map[string]bool{},
	}
}

func (f *fakeIdP) CreateOrganization(_ context.Context, alias, _ string) (string, error) {
	f.nextID++
	id := fmt.Sprintf("kc-%s-%d", alias, f.nextID)
	f.orgs[id] = alias
	return id, nil
}
func (f *fakeIdP) DeleteOrganization(_ context.Context, id string) error {
	delete(f.orgs, id)
	return nil
}
func (f *fakeIdP) CreateGroup(_ context.Context, path string) (string, error) {
	f.groups = append(f.groups, path)
	return "grp-" + path, nil
}
func (f *fakeIdP) ListOrganizations(context.Context, string) ([]string, error) { return nil, nil }
func (f *fakeIdP) AddOrganizationMember(_ context.Context, kcOrgID, userID string) error {
	f.orgMembers[kcOrgID] = append(f.orgMembers[kcOrgID], userID)
	return nil
}
func (f *fakeIdP) RemoveOrganizationMember(_ context.Context, kcOrgID, userID string) error {
	f.orgMembers[kcOrgID] = removeStr(f.orgMembers[kcOrgID], userID)
	return nil
}
func (f *fakeIdP) AddGroupMember(_ context.Context, groupPath, userID string) error {
	f.grpMembers[groupPath] = append(f.grpMembers[groupPath], userID)
	return nil
}
func (f *fakeIdP) RemoveGroupMember(_ context.Context, groupPath, userID string) error {
	f.grpMembers[groupPath] = removeStr(f.grpMembers[groupPath], userID)
	return nil
}
func (f *fakeIdP) GetUser(_ context.Context, userID string) (*types.User, error) {
	if !f.users[userID] {
		return nil, tenancy.ErrUserNotFound
	}
	return &types.User{ID: userID, Email: userID + "@example.com"}, nil
}

func removeStr(s []string, v string) []string {
	out := s[:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

type recordingStore struct {
	written []authz.Tuple
	deleted []authz.Tuple
}

func (r *recordingStore) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (r *recordingStore) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (r *recordingStore) WriteTuples(_ context.Context, t []authz.Tuple) error {
	r.written = append(r.written, t...)
	return nil
}
func (r *recordingStore) DeleteTuples(_ context.Context, t []authz.Tuple) error {
	r.deleted = append(r.deleted, t...)
	return nil
}

func setupDB(t *testing.T) *db.DB {
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

func TestCreateTenantEndToEnd(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())

	org, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Corp")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if !strings.HasPrefix(org.ID, "org:kc-acme") {
		t.Errorf("org.ID = %q", org.ID)
	}
	if len(teams) != 3 {
		t.Fatalf("teams = %d, want 3", len(teams))
	}
	if teams[0].KeycloakGroupPath != "tenant-acme/platform-team" {
		t.Errorf("group path = %q", teams[0].KeycloakGroupPath)
	}
	if len(idp.groups) != 3 {
		t.Errorf("keycloak groups created = %v", idp.groups)
	}

	// Creator auto-membership: Keycloak org + platform-team group.
	if got := idp.orgMembers[org.KeycloakOrgID]; len(got) != 1 || got[0] != "user-1" {
		t.Errorf("org members = %v, want [user-1]", got)
	}
	if got := idp.grpMembers["tenant-acme/platform-team"]; len(got) != 1 || got[0] != "user-1" {
		t.Errorf("platform-team members = %v, want [user-1]", got)
	}

	// Creator membership row with platform-engineer role.
	role, ok, err := tenancy.NewStore().HighestRole(ctx, database.Pool, org.ID, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || role != types.RolePlatformEngineer {
		t.Errorf("creator role = %q, ok=%v", role, ok)
	}

	// Audit rows exist.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(events) != 5 { // 3 teams + 1 tenant + 1 membership
		t.Errorf("audit events = %d, want 5", len(events))
	}

	// Outbox rows pending, then dispatched into tuples.
	rec := &recordingStore{}
	disp := audit.NewDispatcher(database, 50*time.Millisecond, authz.NewTupleWriter(rec))
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(rec.written) != 4 { // 3 team→org role tuples + 1 creator membership
		t.Fatalf("tuples written = %v", rec.written)
	}
	if rec.written[0].Object != "organization:"+org.ID {
		t.Errorf("tuple object = %q", rec.written[0].Object)
	}
	var memberTuple *authz.Tuple
	for i := range rec.written {
		if rec.written[i].Relation == "member" {
			memberTuple = &rec.written[i]
		}
	}
	if memberTuple == nil || memberTuple.User != "user:user-1" {
		t.Fatalf("no creator membership tuple in %v", rec.written)
	}
	if memberTuple.Object != "team:"+teams[0].ID {
		t.Errorf("membership tuple object = %q, want team:%s", memberTuple.Object, teams[0].ID)
	}

	// No unpublished rows remain.
	var pending int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE published_at IS NULL`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Errorf("pending outbox rows = %d", pending)
	}
}

func TestCreateTenantDuplicateSlugRollsBackKeycloak(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	_, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme Again")
	if !errors.Is(err, tenancy.ErrSlugTaken) {
		t.Fatalf("err = %v, want ErrSlugTaken", err)
	}
	if len(idp.orgs) != 1 {
		t.Errorf("keycloak orgs after compensation = %v, want 1", idp.orgs)
	}
}

func TestAuditEventsAppendOnly(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `DELETE FROM audit_events WHERE org_id = $1`, org.ID); err == nil {
		t.Error("expected append-only trigger to reject DELETE")
	}
	if _, err := database.Pool.Exec(ctx, `UPDATE audit_events SET actor = 'x' WHERE org_id = $1`, org.ID); err == nil {
		t.Error("expected append-only trigger to reject UPDATE")
	}
}

var _ = types.Organization{} // keep import if unused in future edits

func TestMembershipLifecycle(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["user-2"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	devTeam := teams[1] // developers

	// Unknown user rejected before any Keycloak/DB write.
	if err := svc.AddMember(ctx, "user-1", "acme", "developers", "ghost"); !errors.Is(err, tenancy.ErrUserNotFound) {
		t.Fatalf("AddMember ghost: %v, want ErrUserNotFound", err)
	}
	// Unknown team.
	if err := svc.AddMember(ctx, "user-1", "acme", "nope", "user-2"); !errors.Is(err, tenancy.ErrTeamNotFound) {
		t.Fatalf("AddMember bad team: %v, want ErrTeamNotFound", err)
	}

	// Happy path add.
	if err := svc.AddMember(ctx, "user-1", "acme", "developers", "user-2"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if got := idp.orgMembers[org.KeycloakOrgID]; len(got) != 2 {
		t.Errorf("org members = %v, want 2", got)
	}
	if got := idp.grpMembers["tenant-acme/developers"]; len(got) != 1 || got[0] != "user-2" {
		t.Errorf("developers members = %v", got)
	}
	role, ok, err := tenancy.NewStore().HighestRole(ctx, database.Pool, org.ID, "user-2")
	if err != nil || !ok || role != types.RoleDeveloper {
		t.Errorf("user-2 role = %q ok=%v err=%v", role, ok, err)
	}

	// List for the console.
	members, err := svc.ListMembers(ctx, org.ID, devTeam.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].UserID != "user-2" || members[0].Email != "user-2@example.com" {
		t.Errorf("members = %+v", members)
	}

	// Outbox dispatch writes the membership tuple.
	rec := &recordingStore{}
	disp := audit.NewDispatcher(database, 50*time.Millisecond, authz.NewTupleWriter(rec))
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	want := authz.Tuple{User: "user:user-2", Relation: "member", Object: "team:" + devTeam.ID}
	found := false
	for _, tp := range rec.written {
		if tp == want {
			found = true
		}
	}
	if !found {
		t.Errorf("tuple %v not written; got %v", want, rec.written)
	}

	// Remove.
	if err := svc.RemoveMember(ctx, "user-1", "acme", "developers", "user-2"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if got := idp.grpMembers["tenant-acme/developers"]; len(got) != 0 {
		t.Errorf("developers members after remove = %v", got)
	}
	if _, ok, _ := tenancy.NewStore().HighestRole(ctx, database.Pool, org.ID, "user-2"); ok {
		t.Error("user-2 still has a role after remove")
	}
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	found = false
	for _, tp := range rec.deleted {
		if tp == want {
			found = true
		}
	}
	if !found {
		t.Errorf("tuple %v not deleted; got %v", want, rec.deleted)
	}

	// Writes are audited.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	var added, removed bool
	for _, e := range events {
		if e.Action == "membership.added" && e.ObjectID == "user-2" {
			added = true
		}
		if e.Action == "membership.removed" && e.ObjectID == "user-2" {
			removed = true
		}
	}
	if !added || !removed {
		t.Errorf("audit membership.added=%v membership.removed=%v", added, removed)
	}
}
