//go:build integration

package tenancy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeIdP struct {
	mu         sync.Mutex
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := fmt.Sprintf("kc-%s-%d", alias, f.nextID)
	f.orgs[id] = alias
	return id, nil
}
func (f *fakeIdP) DeleteOrganization(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.orgs, id)
	return nil
}
func (f *fakeIdP) UpdateOrganization(_ context.Context, id, displayName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.orgs[id]; !ok {
		return tenancy.ErrOrgNotFound
	}
	f.orgs[id] = displayName
	return nil
}
func (f *fakeIdP) DeleteGroup(_ context.Context, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups = removeStr(f.groups, path)
	delete(f.grpMembers, path)
	return nil
}
func (f *fakeIdP) CreateGroup(_ context.Context, path string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups = append(f.groups, path)
	return "grp-" + path, nil
}
func (f *fakeIdP) ListOrganizations(context.Context, string) ([]string, error) { return nil, nil }
func (f *fakeIdP) AddOrganizationMember(_ context.Context, kcOrgID, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orgMembers[kcOrgID] = append(f.orgMembers[kcOrgID], userID)
	return nil
}
func (f *fakeIdP) RemoveOrganizationMember(_ context.Context, kcOrgID, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orgMembers[kcOrgID] = removeStr(f.orgMembers[kcOrgID], userID)
	return nil
}
func (f *fakeIdP) AddGroupMember(_ context.Context, groupPath, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grpMembers[groupPath] = append(f.grpMembers[groupPath], userID)
	return nil
}
func (f *fakeIdP) RemoveGroupMember(_ context.Context, groupPath, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grpMembers[groupPath] = removeStr(f.grpMembers[groupPath], userID)
	return nil
}
func (f *fakeIdP) ListGroupMembers(_ context.Context, groupPath string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.grpMembers[groupPath]...), nil
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
func (r *recordingStore) ReadTuples(context.Context, string, string) ([]authz.Tuple, error) {
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
	if rec.written[0].Object != authz.OrgObject(org.ID) {
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

// Repeated add/remove must not emit duplicate outbox events — OpenFGA rejects
// duplicate writes and deletes of absent tuples, which would stall the
// dispatcher on a poisoned event.
func TestMembershipIdempotent(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["user-2"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	_, teams, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	devTeam := teams[1] // developers

	// Sequential duplicates plus concurrent adds racing on the unique PK:
	// exactly one outbox event must result in all cases.
	for i := 0; i < 2; i++ {
		if err := svc.AddMember(ctx, "user-1", "acme", "developers", "user-2"); err != nil {
			t.Fatalf("AddMember #%d: %v", i, err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.AddMember(ctx, "user-1", "acme", "developers", "user-2")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent AddMember: %v", err)
		}
	}
	rec := &recordingStore{}
	disp := audit.NewDispatcher(database, 50*time.Millisecond, authz.NewTupleWriter(rec))
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	want := authz.Tuple{User: "user:user-2", Relation: "member", Object: "team:" + devTeam.ID}
	writes := 0
	for _, tp := range rec.written {
		if tp == want {
			writes++
		}
	}
	if writes != 1 {
		t.Errorf("membership tuple written %d times, want 1", writes)
	}

	for i := 0; i < 2; i++ {
		if err := svc.RemoveMember(ctx, "user-1", "acme", "developers", "user-2"); err != nil {
			t.Fatalf("RemoveMember #%d: %v", i, err)
		}
	}
	wg = sync.WaitGroup{}
	errs = make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.RemoveMember(ctx, "user-1", "acme", "developers", "user-2")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent RemoveMember: %v", err)
		}
	}
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	deletes := 0
	for _, tp := range rec.deleted {
		if tp == want {
			deletes++
		}
	}
	if deletes != 1 {
		t.Errorf("membership tuple deleted %d times, want 1", deletes)
	}
}

// allowOrgCreator grants only platform:inari org_creator (M1.W2 enforcement).
type allowOrgCreator struct{ allow bool }

func (a allowOrgCreator) Check(_ context.Context, _, relation, object string) (bool, error) {
	if object == authz.ObjectPlatform && relation == authz.RelationOrgCreator {
		return a.allow, nil
	}
	return false, nil
}
func (a allowOrgCreator) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type fixedValidator struct{ id *authn.Identity }

func (v fixedValidator) Validate(context.Context, string) (*authn.Identity, error) { return v.id, nil }

type readyOK struct{}

func (readyOK) Ping(context.Context) error { return nil }

// TestCreateTenantHTTPEnforcement verifies POST /api/v1/tenants is 403 without
// the org_creator tuple and 201 with it (M1.W2).
func TestCreateTenantHTTPEnforcement(t *testing.T) {
	database := setupDB(t)
	newServer := func(allow bool) *httptest.Server {
		idp := newFakeIdP()
		svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
		router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)),
			fixedValidator{id: &authn.Identity{Subject: "user-1"}}, readyOK{})
		tenancy.NewHandler(svc, allowOrgCreator{allow: allow}).RegisterRoutes(api)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		return srv
	}
	post := func(srv *httptest.Server, slug string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/tenants",
			strings.NewReader(`{"slug":"`+slug+`","displayName":"Acme"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	if resp := post(newServer(false), "denied-org"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without tuple: got %d, want 403", resp.StatusCode)
	}

	resp := post(newServer(true), "allowed-org")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with tuple: got %d, want 200", resp.StatusCode)
	}
	var body struct {
		Organization types.Organization `json:"organization"`
		Teams        []types.Team       `json:"teams"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Organization.Slug != "allowed-org" || len(body.Teams) != 3 {
		t.Errorf("body = %+v", body)
	}
}

func TestUpdateTenantProfile(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}

	updated, err := svc.UpdateTenantProfile(ctx, "user-1", "acme", "Acme Incorporated")
	if err != nil {
		t.Fatalf("UpdateTenantProfile: %v", err)
	}
	if updated.DisplayName != "Acme Incorporated" {
		t.Errorf("display name = %q", updated.DisplayName)
	}
	if got := idp.orgs[org.KeycloakOrgID]; got != "Acme Incorporated" {
		t.Errorf("keycloak description = %q", got)
	}
	// Re-read from DB to confirm the projection landed.
	again, err := svc.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if again.DisplayName != "Acme Incorporated" {
		t.Errorf("db display name = %q", again.DisplayName)
	}

	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "organization.updated" && e.ObjectID == org.ID {
			found = true
			if !strings.Contains(string(e.Payload), "Acme Incorporated") {
				t.Errorf("audit payload = %s", e.Payload)
			}
		}
	}
	if !found {
		t.Error("no organization.updated audit event")
	}

	// Unknown org 404s through the service error.
	if _, err := svc.UpdateTenantProfile(ctx, "user-1", "ghost", "X"); !errors.Is(err, tenancy.ErrOrgNotFound) {
		t.Errorf("err = %v, want ErrOrgNotFound", err)
	}
}

func TestTeamLifecycle(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}

	// Create a custom team granting developer.
	team, err := svc.CreateTeam(ctx, "user-1", "acme", "data-science", types.RoleDeveloper)
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if team.Role != types.RoleDeveloper || team.KeycloakGroupPath != "tenant-acme/data-science" {
		t.Errorf("team = %+v", team)
	}
	// Duplicate name conflicts.
	if _, err := svc.CreateTeam(ctx, "user-1", "acme", "data-science", types.RoleViewer); !errors.Is(err, tenancy.ErrTeamNameTaken) {
		t.Fatalf("duplicate: %v, want ErrTeamNameTaken", err)
	}

	// team.created seeds the org role tuple via the outbox.
	rec := &recordingStore{}
	disp := audit.NewDispatcher(database, 50*time.Millisecond, authz.NewTupleWriter(rec))
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	want := authz.Tuple{User: "team:" + team.ID + "#member", Relation: "developer", Object: authz.OrgObject(org.ID)}
	found := false
	for _, tp := range rec.written {
		if tp == want {
			found = true
		}
	}
	if !found {
		t.Errorf("role tuple %v not written; got %v", want, rec.written)
	}

	// Default teams are protected.
	if err := svc.DeleteTeam(ctx, "user-1", "acme", "platform-team"); !errors.Is(err, tenancy.ErrDefaultTeam) {
		t.Fatalf("delete default: %v, want ErrDefaultTeam", err)
	}
	if err := svc.DeleteTeam(ctx, "user-1", "acme", "org-admins"); !errors.Is(err, tenancy.ErrDefaultTeam) {
		t.Fatalf("delete org-admins anchor: %v, want ErrDefaultTeam", err)
	}
	if err := svc.DeleteTeam(ctx, "user-1", "acme", "nope"); !errors.Is(err, tenancy.ErrTeamNotFound) {
		t.Fatalf("delete missing: %v, want ErrTeamNotFound", err)
	}

	// Delete the custom team.
	if err := svc.DeleteTeam(ctx, "user-1", "acme", "data-science"); err != nil {
		t.Fatalf("DeleteTeam: %v", err)
	}
	teams, err := svc.ListTeams(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tm := range teams {
		if tm.Name == "data-science" {
			t.Errorf("team still listed: %+v", tm)
		}
	}
	for _, g := range idp.groups {
		if g == "tenant-acme/data-science" {
			t.Errorf("keycloak group still present: %v", idp.groups)
		}
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
		t.Errorf("role tuple %v not deleted; got %v", want, rec.deleted)
	}

	// Writes are audited.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 30)
	if err != nil {
		t.Fatal(err)
	}
	var created, deleted bool
	for _, e := range events {
		if e.Action == "team.created" && e.ObjectID == team.ID {
			created = true
		}
		if e.Action == "team.deleted" && e.ObjectID == team.ID {
			deleted = true
		}
	}
	if !created || !deleted {
		t.Errorf("audit team.created=%v team.deleted=%v", created, deleted)
	}
}

func TestOrgMemberRoleLifecycle(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["user-2"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}

	// Unknown user rejected.
	if err := svc.SetMemberRole(ctx, "user-1", "acme", "ghost", types.RoleViewer); !errors.Is(err, tenancy.ErrUserNotFound) {
		t.Fatalf("SetMemberRole ghost: %v, want ErrUserNotFound", err)
	}

	// New member via PUT.
	if err := svc.SetMemberRole(ctx, "user-1", "acme", "user-2", types.RoleViewer); err != nil {
		t.Fatalf("SetMemberRole: %v", err)
	}
	if got := idp.orgMembers[org.KeycloakOrgID]; len(got) != 2 {
		t.Errorf("org members = %v, want 2", got)
	}
	if got := idp.grpMembers["tenant-acme/viewers"]; len(got) != 1 || got[0] != "user-2" {
		t.Errorf("viewers members = %v", got)
	}

	// Org-wide view groups per user with highest role.
	members, err := svc.ListOrgMembers(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("org members = %+v", members)
	}
	var u2 *tenancy.OrgMemberView
	for i := range members {
		if members[i].UserID == "user-2" {
			u2 = &members[i]
		}
	}
	if u2 == nil || u2.Role != string(types.RoleViewer) || u2.Email != "user-2@example.com" {
		t.Errorf("user-2 view = %+v", u2)
	}
	if len(u2.Teams) != 1 || u2.Teams[0] != "viewers" {
		t.Errorf("user-2 teams = %v", u2.Teams)
	}

	// Role change: viewer → org-admin (lazily materializes org-admins).
	if err := svc.SetMemberRole(ctx, "user-1", "acme", "user-2", types.RoleOrgAdmin); err != nil {
		t.Fatalf("SetMemberRole org-admin: %v", err)
	}
	if got := idp.grpMembers["tenant-acme/viewers"]; len(got) != 0 {
		t.Errorf("viewers members after change = %v", got)
	}
	if got := idp.grpMembers["tenant-acme/org-admins"]; len(got) != 1 || got[0] != "user-2" {
		t.Errorf("org-admins members = %v", got)
	}
	role, ok, err := tenancy.NewStore().HighestRole(ctx, database.Pool, org.ID, "user-2")
	if err != nil || !ok || role != types.RoleOrgAdmin {
		t.Errorf("user-2 role = %q ok=%v err=%v", role, ok, err)
	}

	// The org-admins team now exists and grants admin via the outbox.
	rec := &recordingStore{}
	disp := audit.NewDispatcher(database, 50*time.Millisecond, authz.NewTupleWriter(rec))
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	adminTuple := false
	for _, tp := range rec.written {
		if tp.Relation == "admin" && tp.Object == authz.OrgObject(org.ID) {
			adminTuple = true
		}
	}
	if !adminTuple {
		t.Errorf("no admin tuple written; got %v", rec.written)
	}

	// Audit: member.added then member.role_changed.
	events, err := audit.NewStore().List(ctx, database.Pool, org.ID, 30)
	if err != nil {
		t.Fatal(err)
	}
	var added, changed bool
	for _, e := range events {
		if e.Action == "member.added" && e.ObjectID == "user-2" {
			added = true
		}
		if e.Action == "member.role_changed" && e.ObjectID == "user-2" {
			changed = true
		}
	}
	if !added || !changed {
		t.Errorf("audit member.added=%v member.role_changed=%v", added, changed)
	}

	// Idempotent re-PUT: no new audit rows.
	if err := svc.SetMemberRole(ctx, "user-1", "acme", "user-2", types.RoleOrgAdmin); err != nil {
		t.Fatal(err)
	}
	events2, _ := audit.NewStore().List(ctx, database.Pool, org.ID, 30)
	if len(events2) != len(events) {
		t.Errorf("idempotent PUT added audit rows: %d -> %d", len(events), len(events2))
	}

	// Remove from the org entirely.
	if err := svc.RemoveOrgMember(ctx, "user-1", "acme", "user-2"); err != nil {
		t.Fatalf("RemoveOrgMember: %v", err)
	}
	if got := idp.orgMembers[org.KeycloakOrgID]; len(got) != 1 {
		t.Errorf("org members after remove = %v, want [user-1]", got)
	}
	if got := idp.grpMembers["tenant-acme/org-admins"]; len(got) != 0 {
		t.Errorf("org-admins members after remove = %v", got)
	}
	if _, ok, _ := tenancy.NewStore().HighestRole(ctx, database.Pool, org.ID, "user-2"); ok {
		t.Error("user-2 still has a role after org removal")
	}
	events3, _ := audit.NewStore().List(ctx, database.Pool, org.ID, 30)
	removedAudit := false
	for _, e := range events3 {
		if e.Action == "member.removed" && e.ObjectID == "user-2" {
			removedAudit = true
		}
	}
	if !removedAudit {
		t.Error("no member.removed audit event")
	}
	if err := disp.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	memberDeleted := false
	for _, tp := range rec.deleted {
		if tp.User == "user:user-2" && tp.Relation == "member" {
			memberDeleted = true
		}
	}
	if !memberDeleted {
		t.Errorf("no membership tuple deleted; got %v", rec.deleted)
	}

	// Removing a non-member is a no-op (idempotent).
	if err := svc.RemoveOrgMember(ctx, "user-1", "acme", "user-2"); err != nil {
		t.Errorf("repeat RemoveOrgMember: %v", err)
	}
}

// TestSetMemberRoleSameRoleDifferentTeam reproduces a membership loss bug:
// memberships are keyed (user_id, org_id, role), so when a user holds role R
// via custom team T and PUT sets role R (anchor team A), the anchor insert
// conflicts and is skipped while T's row is removed — leaving zero rows.
func TestSetMemberRoleSameRoleDifferentTeam(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["user-2"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	org, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTeam(ctx, "user-1", "acme", "ops", types.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(ctx, "user-1", "acme", "ops", "user-2"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetMemberRole(ctx, "user-1", "acme", "user-2", types.RoleViewer); err != nil {
		t.Fatal(err)
	}
	role, ok, err := tenancy.NewStore().HighestRole(ctx, database.Pool, org.ID, "user-2")
	if err != nil || !ok || role != types.RoleViewer {
		t.Errorf("user-2 lost viewer role after same-role PUT: role=%q ok=%v err=%v", role, ok, err)
	}
}

// relationGate grants a fixed relation on any org object (fine PEP stub).
// Like the OpenFGA model, admin implies viewer.
type relationGate struct{ relation string }

func (g relationGate) Check(_ context.Context, _, relation, _ string) (bool, error) {
	if g.relation == "admin" && relation == "viewer" {
		return true, nil
	}
	return relation == g.relation, nil
}
func (g relationGate) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// TestTenantSettingsHTTP verifies the new Settings routes enforce coarse PEP
// (org claim) and fine PEP (org admin for writes, viewer for reads).
func TestTenantSettingsHTTP(t *testing.T) {
	database := setupDB(t)
	ctx := context.Background()
	idp := newFakeIdP()
	idp.users["user-2"] = true
	svc := tenancy.NewService(database, idp, tenancy.NewStore(), audit.NewStore())
	if _, _, err := svc.CreateTenant(ctx, "user-1", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}

	newServer := func(id *authn.Identity, gate relationGate) *httptest.Server {
		router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(nil, nil)), fixedValidator{id: id}, readyOK{})
		tenancy.NewHandler(svc, gate).RegisterRoutes(api)
		srv := httptest.NewServer(router)
		t.Cleanup(srv.Close)
		return srv
	}
	do := func(srv *httptest.Server, method, path, body string) (int, string) {
		var rdr *strings.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		} else {
			rdr = strings.NewReader("")
		}
		req, err := http.NewRequest(method, srv.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			raw = append(raw, buf[:n]...)
			if err != nil {
				break
			}
		}
		return resp.StatusCode, string(raw)
	}

	member := &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}
	stranger := &authn.Identity{Subject: "user-9", Organizations: []string{"other"}}

	adminSrv := newServer(member, relationGate{relation: "admin"})
	viewerSrv := newServer(member, relationGate{relation: "viewer"})
	strangerSrv := newServer(stranger, relationGate{relation: "admin"})

	// Non-member of the org: coarse PEP rejects before any check.
	if code, _ := do(strangerSrv, http.MethodPatch, "/api/v1/tenants/acme", `{"displayName":"X"}`); code != http.StatusForbidden {
		t.Errorf("stranger PATCH: got %d, want 403", code)
	}

	// Viewer-only cannot write.
	if code, _ := do(viewerSrv, http.MethodPatch, "/api/v1/tenants/acme", `{"displayName":"X"}`); code != http.StatusForbidden {
		t.Errorf("viewer PATCH: got %d, want 403", code)
	}
	if code, _ := do(viewerSrv, http.MethodPost, "/api/v1/tenants/acme/teams", `{"name":"x"}`); code != http.StatusForbidden {
		t.Errorf("viewer POST team: got %d, want 403", code)
	}
	if code, _ := do(viewerSrv, http.MethodPut, "/api/v1/tenants/acme/members/user-2", `{"role":"viewer"}`); code != http.StatusForbidden {
		t.Errorf("viewer PUT member: got %d, want 403", code)
	}

	// Viewer can read the org-wide member list.
	if code, body := do(viewerSrv, http.MethodGet, "/api/v1/tenants/acme/members", ""); code != http.StatusOK {
		t.Errorf("viewer GET members: got %d %s, want 200", code, body)
	}

	// Admin: PATCH profile.
	if code, body := do(adminSrv, http.MethodPatch, "/api/v1/tenants/acme", `{"displayName":"Acme Corp"}`); code != http.StatusOK {
		t.Fatalf("admin PATCH: got %d %s, want 200", code, body)
	}

	// Admin: team CRUD.
	if code, body := do(adminSrv, http.MethodPost, "/api/v1/tenants/acme/teams", `{"name":"ops","role":"developer"}`); code != http.StatusOK {
		t.Fatalf("admin POST team: got %d %s, want 200", code, body)
	}
	if code, _ := do(adminSrv, http.MethodPost, "/api/v1/tenants/acme/teams", `{"name":"ops"}`); code != http.StatusConflict {
		t.Errorf("duplicate team: got %d, want 409", code)
	}
	if code, _ := do(adminSrv, http.MethodDelete, "/api/v1/tenants/acme/teams/platform-team", ""); code != http.StatusConflict {
		t.Errorf("delete default team: got %d, want 409", code)
	}
	if code, _ := do(adminSrv, http.MethodDelete, "/api/v1/tenants/acme/teams/ops", ""); code != http.StatusOK && code != http.StatusNoContent {
		t.Errorf("delete team: got %d, want 200/204", code)
	}

	// Admin: member role PUT/DELETE.
	if code, body := do(adminSrv, http.MethodPut, "/api/v1/tenants/acme/members/user-2", `{"role":"developer"}`); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("admin PUT member: got %d %s", code, body)
	}
	if code, _ := do(adminSrv, http.MethodPut, "/api/v1/tenants/acme/members/user-2", `{"role":"bogus"}`); code != http.StatusBadRequest {
		t.Errorf("invalid role: got %d, want 400", code)
	}
	if code, body := do(adminSrv, http.MethodGet, "/api/v1/tenants/acme/members", ""); code != http.StatusOK {
		t.Fatalf("admin GET members: got %d %s", code, body)
	}
	if code, _ := do(adminSrv, http.MethodDelete, "/api/v1/tenants/acme/members/user-2", ""); code != http.StatusOK && code != http.StatusNoContent {
		t.Errorf("admin DELETE member: got %d", code)
	}
}
