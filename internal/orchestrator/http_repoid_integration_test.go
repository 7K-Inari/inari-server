//go:build integration

package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/eventbus/eventbustest"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// repoStoreAdapter binds the inventory store to the gitprovider.RepoStore
// seam (same shape as cmd/inari-server/main.go).
type repoStoreAdapter struct {
	store *inventory.Store
	db    *db.DB
}

func (a repoStoreAdapter) GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	return a.store.GetGitRepo(ctx, a.db.Pool, orgID, id)
}

func (a repoStoreAdapter) GetDefaultGitRepo(ctx context.Context, orgID string) (*types.TenantGitRepo, error) {
	return a.store.GetDefaultGitRepo(ctx, a.db.Pool, orgID)
}

// itServerWithRepoResolver wires the orchestrator with the repo-aware
// resolver (Feature A) over a fake provider, seeding a default baseline
// repo row plus one team-scope repo row.
func itServerWithRepoResolver(t *testing.T) (*httptest.Server, *db.DB, *gitprovider.Fake, *itQueue, string, string) {
	t.Helper()
	database := itDatabase(t)
	ctx := context.Background()
	fake := gitprovider.NewFake()

	// Seed the registry: default baseline (mirrors the tenant_git_configs
	// row seeded by itDatabase) + a team repo.
	if _, err := fake.EnsureRepo(ctx, "inari-dev/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.EnsureRepo(ctx, "inari-dev/team-a-gitops"); err != nil {
		t.Fatal(err)
	}
	invStore := inventory.NewStore()
	baseline := &types.TenantGitRepo{
		OrgID: "org:1", Name: "baseline", Repo: "inari-dev/acme-inari-state",
		Scope: types.GitRepoScopePlatform, CommitPolicy: types.CommitPolicyDirect,
		BaseBranch: "main", IsDefault: true,
	}
	if err := invStore.UpsertGitRepo(ctx, database.Pool, baseline); err != nil {
		t.Fatal(err)
	}
	teamRepo := &types.TenantGitRepo{
		OrgID: "org:1", Name: "team-a", Repo: "inari-dev/team-a-gitops",
		Scope: types.GitRepoScopeTeam, CommitPolicy: types.CommitPolicyDirect,
		BaseBranch: "main",
	}
	if err := invStore.UpsertGitRepo(ctx, database.Pool, teamRepo); err != nil {
		t.Fatal(err)
	}

	auditStore := audit.NewStore()
	tenancySvc := tenancy.NewService(database, nil, tenancy.NewStore(), auditStore)
	catalogSvc := catalog.NewService(database, catalog.NewStore(), nil, auditStore,
		&catalog.FixturePuller{Root: "../catalog/testdata/oci"})
	if _, err := catalogSvc.Sync(ctx); err != nil {
		t.Fatalf("catalog sync: %v", err)
	}
	approvalsSvc := approvals.NewService(database, approvals.NewStore(database), auditStore, tenancySvc, catalogSvc)
	inventorySvc := inventory.NewService(database, inventory.NewStore(), auditStore, catalogSvc)
	queue := &itQueue{}
	resolver := gitprovider.StaticResolver{P: fake}
	repoResolver := gitprovider.NewRepoResolver(repoStoreAdapter{invStore, database}, nil, resolver)
	orchSvc := orchestrator.NewService(database, invStore, catalogSvc, itClusters{},
		approvalsSvc, queue, resolver, auditStore).WithRepoResolver(repoResolver)

	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	catalog.NewHandler(catalogSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	approvals.NewHandler(approvalsSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}, nil).RegisterRoutes(api)
	inventory.NewHandler(inventorySvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	orchestrator.NewHandler(orchSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	return httptest.NewServer(router), database, fake, queue, baseline.ID, teamRepo.ID
}

func deployBody(repoID string) string {
	b := `{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"my-db","namespace":"apps","spec":{"engineVersion":"16","storageGB":50}`
	if repoID != "" {
		b += `,"repoId":"` + repoID + `"`
	}
	return b + `}`
}

func deployInstance(t *testing.T, srv *httptest.Server, body string) orchestrator.DeployResult {
	t.Helper()
	code, respBody := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good", body)
	if code != http.StatusOK {
		t.Fatalf("deploy: %d %s", code, respBody)
	}
	var out struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(respBody), &out); err != nil {
		t.Fatal(err)
	}
	return out.Deploy
}

func instanceRepoID(t *testing.T, database *db.DB, id string) string {
	t.Helper()
	var repoID *string
	if err := database.Pool.QueryRow(context.Background(),
		`SELECT repo_id FROM resource_instances WHERE id = $1`, id).Scan(&repoID); err != nil {
		t.Fatal(err)
	}
	if repoID == nil {
		return ""
	}
	return *repoID
}

// TestDeployWithRepoID pins the Feature A deploy path: an explicit repoId
// commits to the selected repo and records it on the instance.
func TestDeployWithRepoID(t *testing.T) {
	srv, database, git, _, baselineID, teamRepoID := itServerWithRepoResolver(t)
	defer srv.Close()

	d := deployInstance(t, srv, deployBody(teamRepoID))
	files := git.Files("inari-dev/team-a-gitops", "main")
	if _, ok := files["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]; !ok {
		t.Fatalf("instance manifest not committed to team repo: %v", keysOf(files))
	}
	// Nothing landed in the baseline repo.
	if bf := git.Files("inari-dev/acme-inari-state", "main"); len(bf) != 0 {
		t.Fatalf("baseline repo unexpectedly written: %v", keysOf(bf))
	}
	if got := instanceRepoID(t, database, d.InstanceID); got != teamRepoID {
		t.Errorf("instance repo_id = %q, want %q", got, teamRepoID)
	}
	if got := instanceRepoID(t, database, d.InstanceID); got == baselineID {
		t.Errorf("instance repo_id must be the team repo, not baseline %q", baselineID)
	}
}

// TestDeployDefaultRepoBackCompat pins the no-repoId path: the default
// registry repo wins and the instance records it.
func TestDeployDefaultRepoBackCompat(t *testing.T) {
	srv, database, git, _, baselineID, _ := itServerWithRepoResolver(t)
	defer srv.Close()

	d := deployInstance(t, srv, deployBody(""))
	files := git.Files("inari-dev/acme-inari-state", "main")
	if _, ok := files["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]; !ok {
		t.Fatalf("instance manifest not committed to default repo: %v", keysOf(files))
	}
	if got := instanceRepoID(t, database, d.InstanceID); got != baselineID {
		t.Errorf("instance repo_id = %q, want default %q", got, baselineID)
	}
}

// TestDeployUnknownRepoID is a 404 from the registry lookup — even with
// the enforcement seams unwired (this server), the service's
// inventory.ErrRepoNotFound maps to 404, never a bare 500.
func TestDeployUnknownRepoID(t *testing.T) {
	srv, _, _, _, _, _ := itServerWithRepoResolver(t)
	defer srv.Close()

	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good", deployBody("01JUNKNOWNREPOID0000000000"))
	if code != http.StatusNotFound {
		t.Fatalf("unknown repoId: got %d, want 404 (body: %s)", code, body)
	}
}

// TestMutationRepoMismatch pins the 422 contract on upgrade/rollback/update
// when an explicit repoId disagrees with the recorded repo, and the
// recorded-repo resolution on delete.
func TestMutationRepoMismatch(t *testing.T) {
	srv, database, git, _, baselineID, teamRepoID := itServerWithRepoResolver(t)
	defer srv.Close()
	ctx := context.Background()

	d := deployInstance(t, srv, deployBody(teamRepoID))

	// Upgrade with mismatched repoId → 422.
	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/"+d.InstanceID+"/upgrade", "good",
		`{"toVersion":"1.1.0","repoId":"`+baselineID+`"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("upgrade mismatched repoId: got %d, want 422 (%s)", code, body)
	}
	// Update with mismatched repoId → 422.
	code, body = itReq(t, srv, "PATCH", "/api/v1/tenants/acme/instances/"+d.InstanceID, "good",
		`{"spec":{"engineVersion":"16","storageGB":60},"repoId":"`+baselineID+`"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("update mismatched repoId: got %d, want 422 (%s)", code, body)
	}
	// Rollback with mismatched repoId → 422.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/"+d.InstanceID+"/rollback", "good",
		`{"toVersion":"1.0.0","repoId":"`+baselineID+`"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("rollback mismatched repoId: got %d, want 422 (%s)", code, body)
	}

	// Upgrade with the matching repoId succeeds and writes to the team repo.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/"+d.InstanceID+"/upgrade", "good",
		`{"toVersion":"1.1.0","repoId":"`+teamRepoID+`"}`)
	if code != http.StatusOK {
		t.Fatalf("upgrade matching repoId: %d %s", code, body)
	}
	files := git.Files("inari-dev/team-a-gitops", "main")
	inst := files["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]
	if !strings.Contains(inst, "storageGB: 50") {
		t.Errorf("upgraded manifest missing from team repo:\n%s", inst)
	}
	if bf := git.Files("inari-dev/acme-inari-state", "main"); len(bf) != 0 {
		t.Errorf("baseline repo unexpectedly written: %v", keysOf(bf))
	}

	// Delete resolves the recorded repo: files removed from the team repo.
	code, body = itReq(t, srv, "DELETE", "/api/v1/tenants/acme/instances/"+d.InstanceID, "good", "")
	if code != http.StatusOK {
		t.Fatalf("delete: %d %s", code, body)
	}
	files = git.Files("inari-dev/team-a-gitops", "main")
	if _, ok := files["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]; ok {
		t.Error("instance manifest still present in team repo after delete")
	}
	var count int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM resource_instances WHERE id = $1`, d.InstanceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Error("instance row still present after delete")
	}
}

// itServerM3WithRepoResolver is itServerM3 plus the repo-aware resolver and
// the seeded registry rows (default baseline + team repo). Returns the team
// repo's row id for selector assertions.
func itServerM3WithRepoResolver(t *testing.T) (*httptest.Server, *db.DB, *gitprovider.Fake, *itQueue, string, *audit.Dispatcher) {
	t.Helper()
	srv, database, fake, _, _, teamRepoID := itServerWithRepoResolver(t)
	// Rebuild with the dispatcher: itServerWithRepoResolver has no resume
	// wiring, so construct the M3 variant inline over the same database.
	srv.Close()
	ctx := context.Background()

	auditStore := audit.NewStore()
	tenancySvc := tenancy.NewService(database, nil, tenancy.NewStore(), auditStore)
	catalogSvc := catalog.NewService(database, catalog.NewStore(), nil, auditStore,
		&catalog.FixturePuller{Root: "../catalog/testdata/oci"})
	if _, err := catalogSvc.Sync(ctx); err != nil {
		t.Fatalf("catalog sync: %v", err)
	}
	approvalsSvc := approvals.NewService(database, approvals.NewStore(database), auditStore, tenancySvc, catalogSvc)
	inventorySvc := inventory.NewService(database, inventory.NewStore(), auditStore, catalogSvc)
	q := &itQueue{}
	resolver := gitprovider.StaticResolver{P: fake}
	invStore := inventory.NewStore()
	repoResolver := gitprovider.NewRepoResolver(repoStoreAdapter{invStore, database}, nil, resolver)
	orchSvc := orchestrator.NewService(database, invStore, catalogSvc, itClusters{},
		approvalsSvc, q, resolver, auditStore).WithRepoResolver(repoResolver)
	dispatcher := eventbustest.Dispatcher(t, database, time.Millisecond,
		audit.Named("orchestrator-resume", orchestrator.NewResumeHandler(orchSvc, approvalsSvc, slog.Default())))

	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	catalog.NewHandler(catalogSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	approvals.NewHandler(approvalsSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}, nil).RegisterRoutes(api)
	inventory.NewHandler(inventorySvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	orchestrator.NewHandler(orchSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	return httptest.NewServer(router), database, fake, q, teamRepoID, dispatcher
}

// enforcementValidator issues identities with team group claims.
type enforcementValidator struct{}

func (enforcementValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "admin":
		// settings-write bypass (platform team).
		return &authn.Identity{Subject: "user-admin", Organizations: []string{"acme"}}, nil
	case "team-a-member":
		return &authn.Identity{Subject: "user-a", Organizations: []string{"acme"},
			Groups: []string{"/tenant-acme/team-a"}}, nil
	case "team-b-member":
		return &authn.Identity{Subject: "user-b", Organizations: []string{"acme"},
			Groups: []string{"/tenant-acme/team-b"}}, nil
	}
	return nil, errors.New("invalid token")
}

// enforcementAuthorizer grants settings-write only to the admin subject;
// deployments_create to everyone (the coarse gate).
type enforcementAuthorizer struct{}

func (enforcementAuthorizer) Check(_ context.Context, user, relation, _ string) (bool, error) {
	if relation == authz.RelationTenantSettingsWrite {
		return user == "user:user-admin", nil
	}
	return true, nil
}
func (enforcementAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// itServerEnforcement wires the orchestrator handler with the repo-write
// enforcement seams (teams + repos + instances) over the registry.
func itServerEnforcement(t *testing.T) (*httptest.Server, *db.DB, *gitprovider.Fake, string, string) {
	t.Helper()
	database := itDatabase(t)
	ctx := context.Background()
	fake := gitprovider.NewFake()

	if _, err := fake.EnsureRepo(ctx, "inari-dev/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.EnsureRepo(ctx, "inari-dev/team-a-gitops"); err != nil {
		t.Fatal(err)
	}
	// Teams for the group-claim matcher (role_id required by 0029).
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO teams (id, org_id, name, keycloak_group_path, role_id)
		SELECT '11111111-1111-1111-1111-111111111111','org:1','team-a','/tenant-acme/team-a', id FROM roles WHERE org_id='org:1' AND name='editor'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO teams (id, org_id, name, keycloak_group_path, role_id)
		SELECT '22222222-2222-2222-2222-222222222222','org:1','team-b','/tenant-acme/team-b', id FROM roles WHERE org_id='org:1' AND name='editor'`); err != nil {
		t.Fatal(err)
	}
	invStore := inventory.NewStore()
	baseline := &types.TenantGitRepo{
		OrgID: "org:1", Name: "baseline", Repo: "inari-dev/acme-inari-state",
		Scope: types.GitRepoScopePlatform, CommitPolicy: types.CommitPolicyDirect,
		BaseBranch: "main", IsDefault: true,
	}
	if err := invStore.UpsertGitRepo(ctx, database.Pool, baseline); err != nil {
		t.Fatal(err)
	}
	teamRepo := &types.TenantGitRepo{
		OrgID: "org:1", Name: "team-a", Repo: "inari-dev/team-a-gitops",
		Scope: types.GitRepoScopeTeam, TeamID: "11111111-1111-1111-1111-111111111111",
		CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
	}
	if err := invStore.UpsertGitRepo(ctx, database.Pool, teamRepo); err != nil {
		t.Fatal(err)
	}

	auditStore := audit.NewStore()
	tenancySvc := tenancy.NewService(database, nil, tenancy.NewStore(), auditStore)
	catalogSvc := catalog.NewService(database, catalog.NewStore(), nil, auditStore,
		&catalog.FixturePuller{Root: "../catalog/testdata/oci"})
	if _, err := catalogSvc.Sync(ctx); err != nil {
		t.Fatalf("catalog sync: %v", err)
	}
	approvalsSvc := approvals.NewService(database, approvals.NewStore(database), auditStore, tenancySvc, catalogSvc)
	queue := &itQueue{}
	resolver := gitprovider.StaticResolver{P: fake}
	repoResolver := gitprovider.NewRepoResolver(repoStoreAdapter{invStore, database}, nil, resolver)
	orchSvc := orchestrator.NewService(database, invStore, catalogSvc, itClusters{},
		approvalsSvc, queue, resolver, auditStore).WithRepoResolver(repoResolver)

	router, api := httpserver.NewRouter(slog.Default(), enforcementValidator{}, database)
	orchestrator.NewHandler(orchSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, enforcementAuthorizer{}).
		WithRepoWriteEnforcement(tenancySvc, repoStoreAdapter{invStore, database}, instanceGetterAdapter{invStore, database}).
		RegisterRoutes(api)
	return httptest.NewServer(router), database, fake, baseline.ID, teamRepo.ID
}

// instanceGetterAdapter binds inventory.Store to the orchestrator's
// InstanceGetter seam.
type instanceGetterAdapter struct {
	store *inventory.Store
	db    *db.DB
}

func (a instanceGetterAdapter) GetInstance(ctx context.Context, id string) (*types.ResourceInstance, error) {
	return a.store.Get(ctx, a.db.Pool, id)
}

// TestRepoWriteEnforcement pins decision 5b on the deploy path.
func TestRepoWriteEnforcement(t *testing.T) {
	srv, _, _, _, teamRepoID := itServerEnforcement(t)
	defer srv.Close()

	bodyWithRepo := func(name, repoID string) string {
		return `{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"` + name + `","spec":{"engineVersion":"16","storageGB":50},"repoId":"` + repoID + `"}`
	}

	// Team member deploys to own team repo → 200.
	if code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "team-a-member", bodyWithRepo("db-a", teamRepoID)); code != http.StatusOK {
		t.Errorf("own team repo: got %d, want 200 (%s)", code, body)
	}
	// Other team's member → 403.
	if code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "team-b-member", bodyWithRepo("db-b", teamRepoID)); code != http.StatusForbidden {
		t.Errorf("other team repo: got %d, want 403 (%s)", code, body)
	}
	// Settings-write caller → 200.
	if code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "admin", bodyWithRepo("db-c", teamRepoID)); code != http.StatusOK {
		t.Errorf("admin: got %d, want 200 (%s)", code, body)
	}
	// Unknown repo → 404.
	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "team-a-member", bodyWithRepo("db-d", "01JUNKNOWNREPOID0000000000")); code != http.StatusNotFound {
		t.Errorf("unknown repo: got %d, want 404", code)
	}
	// No repoId → no check (default repo, any org member).
	if code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "team-b-member",
		`{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"db-e","spec":{"engineVersion":"16","storageGB":50}}`); code != http.StatusOK {
		t.Errorf("default repo: got %d, want 200 (%s)", code, body)
	}
}

// TestRepoWriteEnforcementOnMutations pins the recorded-repo check on
// upgrade/delete: a user who is not in the owning team cannot mutate.
func TestRepoWriteEnforcementOnMutations(t *testing.T) {
	srv, _, _, _, teamRepoID := itServerEnforcement(t)
	defer srv.Close()

	// Admin deploys to the team repo.
	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "admin",
		`{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"db-x","spec":{"engineVersion":"16","storageGB":50},"repoId":"`+teamRepoID+`"}`)
	if code != http.StatusOK {
		t.Fatalf("deploy: %d %s", code, body)
	}

	// team-b member cannot upgrade or delete the team-a instance.
	if code, _ := itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/db-x/upgrade", "team-b-member", `{"toVersion":"1.1.0"}`); code != http.StatusForbidden {
		t.Errorf("other-team upgrade: got %d, want 403", code)
	}
	if code, _ := itReq(t, srv, "DELETE", "/api/v1/tenants/acme/instances/db-x", "team-b-member", ""); code != http.StatusForbidden {
		t.Errorf("other-team delete: got %d, want 403", code)
	}
	// Owning team member can.
	if code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/db-x/upgrade", "team-a-member", `{"toVersion":"1.1.0"}`); code != http.StatusOK {
		t.Errorf("own-team upgrade: got %d, want 200 (%s)", code, body)
	}
}

// TestApprovalResumePreservesRepoID pins the gated-deploy path: the repoId
// chosen at request time survives the approval round-trip and the resumed
// deploy commits to the selected repo.
func TestApprovalResumePreservesRepoID(t *testing.T) {
	srv, database, git, queue, teamRepoID, dispatcher := itServerM3WithRepoResolver(t)
	defer srv.Close()
	ctx := context.Background()

	if _, err := database.Pool.Exec(ctx,
		`UPDATE catalog_items SET approval_policy = 'peer' WHERE id = 'curated:web-service'`); err != nil {
		t.Fatal(err)
	}

	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"curated:web-service","version":"0.1.0","clusterId":"cluster-1","name":"web","namespace":"apps","spec":{"hostname":"app.example.com"},"repoId":"`+teamRepoID+`"}`)
	if code != http.StatusOK {
		t.Fatalf("gated deploy: %d %s", code, body)
	}
	var out struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Deploy.Status != "pending_approval" {
		t.Fatalf("expected pending_approval, got %+v", out.Deploy)
	}
	// The approval request persisted the selector.
	var repoID *string
	if err := database.Pool.QueryRow(ctx,
		`SELECT repo_id FROM approval_requests WHERE id = $1`, out.Deploy.ApprovalID).Scan(&repoID); err != nil {
		t.Fatal(err)
	}
	if repoID == nil || *repoID != teamRepoID {
		t.Fatalf("approval repo_id = %v, want %q", repoID, teamRepoID)
	}

	// Peer approves → outbox event → resume commits to the team repo.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/approvals/"+out.Deploy.ApprovalID+"/decide", "peer", `{"approve":true}`)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, body)
	}
	if err := eventbustest.DispatchOnce(ctx, dispatcher); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(queue.cmds) != 1 {
		t.Fatalf("queued commands after resume = %d, want 1", len(queue.cmds))
	}
	files := git.Files("inari-dev/team-a-gitops", "main")
	if _, ok := files["clusters/cluster-1/web-service/web/instance.yaml"]; !ok {
		t.Fatalf("resumed deploy not committed to team repo: %v", keysOf(files))
	}
	if bf := git.Files("inari-dev/acme-inari-state", "main"); len(bf) != 0 {
		t.Errorf("baseline repo unexpectedly written: %v", keysOf(bf))
	}
}

// TestQALegacyInstanceMutation pins the back-compat path for pre-0036
// instances (repo_id NULL): mutations resolve the org default repo, accept
// only the empty/"default" selector, and self-heal the attribution —
// MarkDeployed backfills repo_id to the repo the mutation just wrote
// (COALESCE: an already-attributed row is never moved).
func TestQALegacyInstanceMutation(t *testing.T) {
	srv, database, git, _, baselineID, teamRepoID := itServerWithRepoResolver(t)
	defer srv.Close()
	ctx := context.Background()

	d := deployInstance(t, srv, deployBody(""))
	// Simulate a pre-0036 row: clear the recorded repo.
	if _, err := database.Pool.Exec(ctx,
		`UPDATE resource_instances SET repo_id = NULL WHERE id = $1`, d.InstanceID); err != nil {
		t.Fatal(err)
	}

	// An explicit repoId naming the default ROW ID is accepted for legacy
	// rows (their manifests live in the default repo by definition).
	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/"+d.InstanceID+"/upgrade", "good",
		`{"toVersion":"1.1.0","repoId":"`+baselineID+`"}`)
	if code != http.StatusOK {
		t.Fatalf("legacy upgrade with default row id: got %d, want 200 (%s)", code, body)
	}
	// A team repo id is rejected (422) — the legacy row's manifests are not
	// there.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/"+d.InstanceID+"/upgrade", "good",
		`{"toVersion":"1.1.0","repoId":"`+teamRepoID+`"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("legacy upgrade with team repo id: got %d, want 422 (%s)", code, body)
	}

	// No selector: upgrade lands in the default repo.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/"+d.InstanceID+"/upgrade", "good",
		`{"toVersion":"1.1.0"}`)
	if code != http.StatusOK {
		t.Fatalf("legacy upgrade: %d %s", code, body)
	}
	files := git.Files("inari-dev/acme-inari-state", "main")
	if _, ok := files["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]; !ok {
		t.Fatalf("legacy upgrade not committed to default repo: %v", keysOf(files))
	}
	// The mutation self-heals the attribution: repo_id backfills to the
	// default repo the upgrade wrote to.
	if got := instanceRepoID(t, database, d.InstanceID); got != baselineID {
		t.Errorf("legacy instance repo_id = %q after upgrade, want backfilled default %q", got, baselineID)
	}

	// Delete resolves the default repo for the legacy row.
	code, body = itReq(t, srv, "DELETE", "/api/v1/tenants/acme/instances/"+d.InstanceID, "good", "")
	if code != http.StatusOK {
		t.Fatalf("legacy delete: %d %s", code, body)
	}
	if _, ok := git.Files("inari-dev/acme-inari-state", "main")["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]; ok {
		t.Error("legacy instance manifest still present in default repo after delete")
	}
}
