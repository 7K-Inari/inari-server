package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/types"
)

// catalogFixture extends stepsFixture with completed creating-repo and
// pending registering-catalog/binding-rbac steps.
func catalogFixture(t *testing.T, values string) (*RunContext, *types.ScaffoldRunStep, *types.ScaffoldRunStep) {
	t.Helper()
	rc, repo, _ := stepsFixture(t, values)
	repo.State = types.ScaffoldStepCompleted
	repo.Result = json.RawMessage(`{"repoName":"inari-apps/acme-payments-api","repoUrl":"https://fake.git/inari-apps/acme-payments-api.git","branch":"main","commitSha":"abc"}`)
	cat := &types.ScaffoldRunStep{RunID: rc.Run.ID, Name: "registering-catalog", State: types.ScaffoldStepPending, MaxAttempts: 5}
	rbac := &types.ScaffoldRunStep{RunID: rc.Run.ID, Name: "binding-rbac", State: types.ScaffoldStepPending, MaxAttempts: 5}
	rc.Steps["registering-catalog"] = cat
	rc.Steps["binding-rbac"] = rbac
	return rc, cat, rbac
}

func TestRegisteringCatalogHappyPath(t *testing.T) {
	rc, cat, _ := catalogFixture(t, `{"name":"payments-api"}`)
	up := &fakeUpserter{}

	done, err := stepRegisteringCatalog(context.Background(), &ExecEnv{Upsert: up}, rc, cat)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(up.items) != 1 || len(up.versions) != 1 {
		t.Fatalf("upserts: items=%d versions=%d", len(up.items), len(up.versions))
	}
	item := up.items[0]
	if item.ID != "component:acme-payments-api" {
		t.Fatalf("item ID = %q", item.ID)
	}
	if item.Source != types.CatalogSourcePlatform {
		t.Fatalf("source = %q", item.Source)
	}
	if item.Name != "payments-api" || item.DisplayName != "payments-api" {
		t.Fatalf("name/displayName = %q/%q", item.Name, item.DisplayName)
	}
	if item.OrgID != "org:acme" {
		t.Fatalf("item orgID = %q", item.OrgID)
	}
	ver := up.versions[0]
	if ver.ItemID != item.ID || ver.Version == "" {
		t.Fatalf("version = %+v", ver)
	}
	var payload map[string]any
	if err := json.Unmarshal(ver.Payload, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if payload["orgId"] != "org:acme" || payload["orgSlug"] != "acme" {
		t.Fatalf("payload org labels = %v", payload)
	}
	if payload["repoUrl"] != "https://fake.git/inari-apps/acme-payments-api.git" {
		t.Fatalf("payload repoUrl = %v", payload["repoUrl"])
	}
	if payload["owningTeam"] != "payments-api-maintainers" {
		t.Fatalf("payload owningTeam = %v", payload["owningTeam"])
	}
	var res registerCatalogResult
	if err := json.Unmarshal(cat.Result, &res); err != nil || res.CatalogItemID != item.ID {
		t.Fatalf("step result = %s (%v)", cat.Result, err)
	}
	var outputs map[string]any
	if err := json.Unmarshal(rc.Run.Outputs, &outputs); err != nil || outputs["catalogItemId"] != item.ID {
		t.Fatalf("outputs = %s (%v)", rc.Run.Outputs, err)
	}
}

func TestRegisteringCatalogIdempotentReentry(t *testing.T) {
	rc, cat, _ := catalogFixture(t, `{"name":"payments-api"}`)
	cat.Result = json.RawMessage(`{"catalogItemId":"component:acme-payments-api","repoUrl":"https://fake.git/x.git"}`)
	up := &fakeUpserter{}

	done, err := stepRegisteringCatalog(context.Background(), &ExecEnv{Upsert: up}, rc, cat)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(up.items) != 0 {
		t.Fatalf("re-entry upserted %d items", len(up.items))
	}
}

func TestRegisteringCatalogTransientErrorRetry(t *testing.T) {
	rc, cat, _ := catalogFixture(t, `{"name":"payments-api"}`)
	up := &fakeUpserter{err: errors.New("db down")}
	env := &ExecEnv{Upsert: up}

	if _, err := stepRegisteringCatalog(context.Background(), env, rc, cat); err == nil {
		t.Fatal("first attempt must surface the error")
	}
	if len(cat.Result) != 0 {
		t.Fatalf("failed attempt wrote a result: %s", cat.Result)
	}
	up.err = nil
	done, err := stepRegisteringCatalog(context.Background(), env, rc, cat)
	if err != nil || !done || len(up.items) != 1 {
		t.Fatalf("retry: done=%v err=%v items=%d", done, err, len(up.items))
	}
}

func TestRegisteringCatalogGuards(t *testing.T) {
	rc, cat, _ := catalogFixture(t, `{"name":"payments-api"}`)

	if _, err := stepRegisteringCatalog(context.Background(), &ExecEnv{}, rc, cat); err == nil {
		t.Fatal("nil catalog upserter must fail")
	}
	bare := &RunContext{Run: rc.Run, Steps: map[string]*types.ScaffoldRunStep{}, Tenant: rc.Tenant}
	if _, err := stepRegisteringCatalog(context.Background(), &ExecEnv{Upsert: &fakeUpserter{}}, bare, cat); err == nil {
		t.Fatal("missing creating-repo result must fail")
	}
	noTenant := &RunContext{Run: rc.Run, Steps: rc.Steps}
	if _, err := stepRegisteringCatalog(context.Background(), &ExecEnv{Upsert: &fakeUpserter{}}, noTenant, cat); err == nil {
		t.Fatal("missing tenant context must fail")
	}
}

// fakeRBACBinder records EnsureTeam/AddMember calls and can fail the next
// AddMember (transient error retry tests).
type fakeRBACBinder struct {
	teams      []ensureTeamCall
	members    []addMemberCall
	failNext   bool
	teamExists bool
}

type ensureTeamCall struct {
	Actor, Slug, Name string
	Role              types.Role
}

type addMemberCall struct {
	Actor, Slug, Team, UserID string
}

func (f *fakeRBACBinder) EnsureTeam(_ context.Context, actor, slug, name string, role types.Role) (*types.Team, error) {
	f.teams = append(f.teams, ensureTeamCall{actor, slug, name, role})
	return &types.Team{
		ID: "team:" + name, OrgID: "org:acme", Name: name, Role: role,
		KeycloakGroupPath: "tenant-" + slug + "/" + name,
	}, nil
}

func (f *fakeRBACBinder) AddMember(_ context.Context, actor, slug, teamName, userID string) error {
	if f.failNext {
		f.failNext = false
		return errors.New("keycloak 503")
	}
	f.members = append(f.members, addMemberCall{actor, slug, teamName, userID})
	return nil
}

func TestBindingRBACHappyPath(t *testing.T) {
	rc, _, rbac := catalogFixture(t, `{"name":"payments-api"}`)
	rc.Run.CreatedBy = "user:dev-1"
	b := &fakeRBACBinder{}

	done, err := stepBindingRBAC(context.Background(), &ExecEnv{RBAC: b}, rc, rbac)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(b.teams) != 1 {
		t.Fatalf("EnsureTeam calls = %+v", b.teams)
	}
	team := b.teams[0]
	if team.Slug != "acme" || team.Name != "payments-api-maintainers" || team.Role != types.RoleDeveloper {
		t.Fatalf("EnsureTeam = %+v", team)
	}
	if len(b.members) != 1 {
		t.Fatalf("AddMember calls = %+v", b.members)
	}
	m := b.members[0]
	if m.Team != "payments-api-maintainers" || m.UserID != "user:dev-1" || m.Slug != "acme" {
		t.Fatalf("AddMember = %+v", m)
	}
	var res bindRBACResult
	if err := json.Unmarshal(rbac.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.TeamID != "team:payments-api-maintainers" ||
		res.GroupPath != "tenant-acme/payments-api-maintainers" ||
		res.Role != string(types.RoleDeveloper) || res.Member != "user:dev-1" {
		t.Fatalf("result = %+v", res)
	}
}

func TestBindingRBACIdempotentReentry(t *testing.T) {
	rc, _, rbac := catalogFixture(t, `{"name":"payments-api"}`)
	rbac.Result = json.RawMessage(`{"teamId":"team:x","teamName":"payments-api-maintainers","groupPath":"tenant-acme/payments-api-maintainers","role":"developer","member":"user:dev-1"}`)
	b := &fakeRBACBinder{}

	done, err := stepBindingRBAC(context.Background(), &ExecEnv{RBAC: b}, rc, rbac)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(b.teams) != 0 || len(b.members) != 0 {
		t.Fatalf("re-entry hit the binder: teams=%v members=%v", b.teams, b.members)
	}
}

func TestBindingRBACTransientErrorRetry(t *testing.T) {
	rc, _, rbac := catalogFixture(t, `{"name":"payments-api"}`)
	rc.Run.CreatedBy = "user:dev-1"
	b := &fakeRBACBinder{failNext: true}
	env := &ExecEnv{RBAC: b}

	if _, err := stepBindingRBAC(context.Background(), env, rc, rbac); err == nil {
		t.Fatal("first attempt must surface the transient error")
	}
	if len(rbac.Result) != 0 {
		t.Fatalf("failed attempt wrote a result: %s", rbac.Result)
	}
	done, err := stepBindingRBAC(context.Background(), env, rc, rbac)
	if err != nil || !done {
		t.Fatalf("retry: done=%v err=%v", done, err)
	}
	// EnsureTeam is idempotent: the retry re-ensures the team, then adds
	// the member exactly once.
	if len(b.teams) != 2 || len(b.members) != 1 {
		t.Fatalf("teams=%d members=%d", len(b.teams), len(b.members))
	}
}

func TestBindingRBACGuards(t *testing.T) {
	rc, _, rbac := catalogFixture(t, `{"name":"payments-api"}`)

	if _, err := stepBindingRBAC(context.Background(), &ExecEnv{}, rc, rbac); err == nil {
		t.Fatal("nil RBAC binder must fail")
	}
	noTenant := &RunContext{Run: rc.Run, Steps: rc.Steps}
	if _, err := stepBindingRBAC(context.Background(), &ExecEnv{RBAC: &fakeRBACBinder{}}, noTenant, rbac); err == nil {
		t.Fatal("missing tenant context must fail")
	}
}

func TestBindingRBACManifestRoleOverride(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0",
		testScaffoldBlock+"  bindRbac:\n    role: platform-engineer\n", map[string]string{"a.txt": "x"})
	rc, _, rbac := catalogFixture(t, `{"name":"payments-api"}`)
	b := &fakeRBACBinder{}
	env := &ExecEnv{RBAC: b, Templates: &FilePuller{Root: dir}}

	done, err := stepBindingRBAC(context.Background(), env, rc, rbac)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if b.teams[0].Role != types.RolePlatformEngineer {
		t.Fatalf("role = %q", b.teams[0].Role)
	}
}

func TestBindingRBACRejectsInvalidManifestRole(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0",
		testScaffoldBlock+"  bindRbac:\n    role: superuser\n", map[string]string{"a.txt": "x"})
	rc, _, rbac := catalogFixture(t, `{"name":"payments-api"}`)
	b := &fakeRBACBinder{}
	env := &ExecEnv{RBAC: b, Templates: &FilePuller{Root: dir}}

	if _, err := stepBindingRBAC(context.Background(), env, rc, rbac); err == nil {
		t.Fatal("invalid role must fail")
	}
	if len(b.teams) != 0 {
		t.Fatal("invalid role hit the binder before validation")
	}
}

// recordingTuples is an authz.Store fake capturing written tuples.
type recordingTuples struct {
	written []authz.Tuple
}

func (r *recordingTuples) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (r *recordingTuples) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (r *recordingTuples) ReadTuples(context.Context, string, string) ([]authz.Tuple, error) {
	return nil, nil
}
func (r *recordingTuples) WriteTuples(_ context.Context, t []authz.Tuple) error {
	r.written = append(r.written, t...)
	return nil
}
func (r *recordingTuples) DeleteTuples(context.Context, []authz.Tuple) error { return nil }

func hasTuple(tuples []authz.Tuple, t authz.Tuple) bool {
	for _, x := range tuples {
		if x == t {
			return true
		}
	}
	return false
}

// TestRBACOutboxPayloadsFeedTupleWriter pins the contract between the
// tenancy outbox events binding-rbac relies on (EventTeamCreated +
// EventMembershipAdded) and the OpenFGA tuple writer: the maintainers team
// grants its org role, and the creator joins the team. Combined with the
// catalog item's org parent tuple (EventCatalogItemUpserted with OrgID,
// emitted by catalog.UpsertItem for the component record), the team gets
// deployer/viewer on the component's catalog item via the FGA model's
// "from parent" relations.
func TestRBACOutboxPayloadsFeedTupleWriter(t *testing.T) {
	rec := &recordingTuples{}
	w := authz.NewTupleWriter(rec)
	ctx := context.Background()

	teamEvent := func() *types.OutboxEvent {
		raw, err := json.Marshal(types.TeamCreatedPayload{
			OrgID: "org:acme", TeamID: "team:payments-api-maintainers",
			Name: "payments-api-maintainers", Role: types.RoleDeveloper,
		})
		if err != nil {
			t.Fatal(err)
		}
		return &types.OutboxEvent{EventType: types.EventTeamCreated, Payload: raw}
	}()
	if err := w.Handle(ctx, teamEvent); err != nil {
		t.Fatalf("team.created: %v", err)
	}
	memberRaw, err := json.Marshal(types.MembershipPayload{
		OrgID: "org:acme", TeamID: "team:payments-api-maintainers",
		UserID: "user:dev-1", Role: types.RoleDeveloper,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Handle(ctx, &types.OutboxEvent{EventType: types.EventMembershipAdded, Payload: memberRaw}); err != nil {
		t.Fatalf("membership.added: %v", err)
	}
	catalogRaw, err := json.Marshal(types.CatalogItemPayload{
		OrgID: "org:acme", ItemID: "component:acme-payments-api", Source: string(types.CatalogSourcePlatform),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Handle(ctx, &types.OutboxEvent{EventType: types.EventCatalogItemUpserted, Payload: catalogRaw}); err != nil {
		t.Fatalf("catalog.item_upserted: %v", err)
	}

	want := []authz.Tuple{
		{User: authz.TeamMemberUserset("team:payments-api-maintainers"), Relation: authz.RelationDeveloper, Object: authz.OrgObject("org:acme")},
		{User: authz.UserObject("user:dev-1"), Relation: authz.RelationMember, Object: authz.TeamObject("team:payments-api-maintainers")},
		{User: authz.OrgObject("org:acme"), Relation: authz.RelationParent, Object: authz.CatalogItemObject("component:acme-payments-api")},
	}
	for _, tuple := range want {
		if !hasTuple(rec.written, tuple) {
			t.Fatalf("missing tuple %+v in %+v", tuple, rec.written)
		}
	}
}
