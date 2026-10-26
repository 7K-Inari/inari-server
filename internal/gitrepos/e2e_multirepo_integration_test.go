//go:build integration

package gitrepos_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/gitrepos"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// e2eFixture wires the gitrepos AND orchestrator handlers over one database,
// one fake git host, and one agent-command queue — the full multi-repo flow
// (register → attach → deploy → undeploy) against the real HTTP stack.
type e2eFixture struct {
	srv      *httptest.Server
	database *db.DB
	git      *gitprovider.Fake
	queue    *itQueue
}

// e2eRepoStoreAdapter binds the inventory store to the gitprovider.RepoStore
// seam (same shape as cmd/inari-server/main.go).
type e2eRepoStoreAdapter struct {
	store *inventory.Store
	db    *db.DB
}

func (a e2eRepoStoreAdapter) GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	return a.store.GetGitRepo(ctx, a.db.Pool, orgID, id)
}

func (a e2eRepoStoreAdapter) GetDefaultGitRepo(ctx context.Context, orgID string) (*types.TenantGitRepo, error) {
	return a.store.GetDefaultGitRepo(ctx, a.db.Pool, orgID)
}

// e2eClusters resolves the seeded cluster for the orchestrator.
type e2eClusters struct{}

func (e2eClusters) GetCluster(_ context.Context, id string) (*types.Cluster, error) {
	if id == "cluster-1" {
		return &types.Cluster{ID: "cluster-1", OrgID: "org:1", Name: "kind-dev", State: types.ClusterStateActive}, nil
	}
	return nil, inventory.ErrInstanceNotFound
}

func newE2EServer(t *testing.T) *e2eFixture {
	t.Helper()
	f := newITServer(t) // seeds org/roles/teams/cluster, wires gitrepos routes
	ctx := context.Background()

	// The deploy path needs the catalog synced and the orchestrator wired
	// with the repo-aware resolver over the SAME database + fake git.
	invStore := inventory.NewStore()
	auditStore := audit.NewStore()
	tenancySvc := tenancy.NewService(f.database, nil, tenancy.NewStore(), auditStore)
	catalogSvc := catalog.NewService(f.database, catalog.NewStore(), nil, auditStore,
		&catalog.FixturePuller{Root: "../catalog/testdata/oci"})
	if _, err := catalogSvc.Sync(ctx); err != nil {
		t.Fatalf("catalog sync: %v", err)
	}
	approvalsSvc := approvals.NewService(f.database, approvals.NewStore(f.database), auditStore, tenancySvc, catalogSvc)
	resolver := gitprovider.StaticResolver{P: f.git}
	repoResolver := gitprovider.NewRepoResolver(e2eRepoStoreAdapter{invStore, f.database}, nil, resolver)
	orchSvc := orchestrator.NewService(f.database, invStore, catalogSvc, e2eClusters{},
		approvalsSvc, f.queue, resolver, auditStore).WithRepoResolver(repoResolver)

	// Rebuild the router with both modules mounted.
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, f.database)
	gitreposSvc := gitrepos.NewService(invStore,
		gitprovider.NewRepoResolver(nil, nil, resolver), f.queue, auditStore, f.database)
	gitrepos.NewHandler(gitreposSvc, tenancySvc, itAuthorizer{}).RegisterRoutes(api)
	orchestrator.NewHandler(orchSvc, e2eTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{}).RegisterRoutes(api)

	f.srv.Close()
	f.srv = httptest.NewServer(router)
	return &e2eFixture{srv: f.srv, database: f.database, git: f.git, queue: f.queue}
}

// req issues one authenticated JSON request against the fixture server.
func (f *e2eFixture) req(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	itf := &itFixture{srv: f.srv}
	return itf.req(t, method, path, token, body)
}

// e2eTenants is the orchestrator handler's tenant resolver seam.
type e2eTenants map[string]*types.Organization

func (t e2eTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := t[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

// TestTeamRepoEndToEnd walks the full multi-repo flow (plan §4.1):
// register a team repo → its root app lands in the baseline repo → a deploy
// targeting the team repo commits there (not the baseline) → undeploy
// removes from the team repo.
func TestTeamRepoEndToEnd(t *testing.T) {
	f := newE2EServer(t)
	defer f.srv.Close()
	ctx := context.Background()
	base := "/api/v1/tenants/acme/git-repos"

	// Register the default baseline via the git-repos API.
	code, body := f.req(t, "POST", base, "admin",
		`{"name":"baseline","repo":"acme/acme-inari-state","scope":"platform","isDefault":true}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register baseline: %d %s", code, body)
	}
	if _, err := f.git.EnsureRepo(ctx, "acme/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.git.EnsureRepo(ctx, "acme/team-a-gitops"); err != nil {
		t.Fatal(err)
	}

	// Register the team repo → root app attach commits into the baseline.
	code, body = f.req(t, "POST", base, "admin",
		`{"name":"team-a","repo":"acme/team-a-gitops","scope":"team","teamId":"11111111-1111-1111-1111-111111111111"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register team repo: %d %s", code, body)
	}
	var regOut struct {
		Repo repoView `json:"repo"`
	}
	if err := json.Unmarshal([]byte(body), &regOut); err != nil {
		t.Fatal(err)
	}
	teamRepoID := regOut.Repo.ID

	rootApp, ok := f.git.Files("acme/acme-inari-state", "main")["gitops-repos/team-a/root-app.yaml"]
	if !ok {
		t.Fatalf("root app not committed to baseline: %v", f.git.Files("acme/acme-inari-state", "main"))
	}
	for _, want := range []string{"kind: Application", "acme/team-a-gitops", "selfHeal: true", "prune: true"} {
		if !strings.Contains(rootApp, want) {
			t.Errorf("root app missing %q:\n%s", want, rootApp)
		}
	}

	// Deploy targeting the team repo → manifests land there, not baseline.
	code, body = f.req(t, "POST", "/api/v1/tenants/acme/deploys", "admin",
		`{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"my-db","namespace":"apps","spec":{"engineVersion":"16","storageGB":50},"repoId":"`+teamRepoID+`"}`)
	if code != http.StatusOK {
		t.Fatalf("deploy: %d %s", code, body)
	}
	var deployOut struct {
		Deploy struct {
			InstanceID string `json:"instanceId"`
		} `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &deployOut); err != nil {
		t.Fatal(err)
	}
	instanceID := deployOut.Deploy.InstanceID

	teamFiles := f.git.Files("acme/team-a-gitops", "main")
	if _, ok := teamFiles["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]; !ok {
		t.Fatalf("instance manifest not committed to team repo: %v", teamFiles)
	}
	// Baseline holds only the root app — no workload manifests.
	for p := range f.git.Files("acme/acme-inari-state", "main") {
		if strings.HasPrefix(p, "clusters/") {
			t.Errorf("workload manifest unexpectedly in baseline: %s", p)
		}
	}

	// Instance row attributes the team repo.
	var recorded string
	if err := f.database.Pool.QueryRow(ctx,
		`SELECT repo_id FROM resource_instances WHERE id = $1`, instanceID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != teamRepoID {
		t.Errorf("instance repo_id = %q, want %q", recorded, teamRepoID)
	}

	// Undeploy → files removed from the TEAM repo; baseline untouched;
	// agent app-deletion command enqueued.
	code, body = f.req(t, "DELETE", "/api/v1/tenants/acme/instances/"+instanceID, "admin", "")
	if code != http.StatusOK {
		t.Fatalf("undeploy: %d %s", code, body)
	}
	if _, ok := f.git.Files("acme/team-a-gitops", "main")["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]; ok {
		t.Error("instance manifest still present in team repo after undeploy")
	}
	var foundDelete bool
	for _, d := range f.git.Deletions {
		if d.Repo == "acme/team-a-gitops" {
			foundDelete = true
		}
		if d.Repo == "acme/acme-inari-state" {
			t.Errorf("undeploy deleted from baseline: %v", d.Paths)
		}
	}
	if !foundDelete {
		t.Error("no DeleteFiles call against the team repo")
	}
	if len(f.queue.cmds) == 0 {
		t.Error("no agent app-deletion command enqueued")
	}
}
