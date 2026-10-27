//go:build integration

package gitrepos_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/gitrepos"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

// itValidator maps tokens to identities with group memberships.
type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "admin": // org admin / platform team: settings-write
		return &authn.Identity{Subject: "admin-1", Organizations: []string{"acme"}}, nil
	case "dev-a": // team-a member
		return &authn.Identity{Subject: "dev-a1", Organizations: []string{"acme"}, Groups: []string{"/tenant-acme/team-a"}}, nil
	case "dev-b": // team-b member
		return &authn.Identity{Subject: "dev-b1", Organizations: []string{"acme"}, Groups: []string{"/tenant-acme/team-b"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "x", Organizations: []string{"other"}}, nil
	}
	return nil, errors.New("invalid token")
}

// itAuthorizer grants relations per subject (mirrors the seeded roles).
type itAuthorizer struct{}

func (itAuthorizer) Check(_ context.Context, user, relation, _ string) (bool, error) {
	switch user {
	case "user:admin-1":
		return true, nil // admin: all relations
	case "user:dev-a1", "user:dev-b1":
		// devs: read + deploy, no settings-write
		return relation == "tenant_read" || relation == "deployments_create", nil
	}
	return false, nil
}

func (itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itQueue struct{ cmds []types.AgentCommand }

func (q *itQueue) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	q.cmds = append(q.cmds, *cmd)
	return nil
}

// itFixture bundles the test server with its dependencies.
type itFixture struct {
	srv      *httptest.Server
	database *db.DB
	git      *gitprovider.Fake
	queue    *itQueue
	svc      *gitrepos.Service
}

func newITServer(t *testing.T) *itFixture {
	t.Helper()
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	seed := `
		INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO roles (org_id, name, display_name, builtin, permissions) VALUES
		  ('org:1','operator','Platform Engineer',true,'["tenant.read","tenant.settings.write","deployments.create"]'),
		  ('org:1','editor','Developer',true,'["tenant.read","deployments.create"]');
		INSERT INTO teams (id, org_id, name, role_id, keycloak_group_path) SELECT
		  '11111111-1111-1111-1111-111111111111', 'org:1', 'team-a', id, '/tenant-acme/team-a' FROM roles WHERE org_id='org:1' AND name='editor';
		INSERT INTO teams (id, org_id, name, role_id, keycloak_group_path) SELECT
		  '22222222-2222-2222-2222-222222222222', 'org:1', 'team-b', id, '/tenant-acme/team-b' FROM roles WHERE org_id='org:1' AND name='editor';
		INSERT INTO clusters (id, org_id, name, state) VALUES ('cluster-1','org:1','kind-dev','active');`
	if _, err := database.Pool.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}

	auditStore := audit.NewStore()
	tenancySvc := tenancy.NewService(database, nil, tenancy.NewStore(), auditStore)
	fake := gitprovider.NewFake()
	queue := &itQueue{}
	svc := gitrepos.NewService(inventory.NewStore(),
		gitprovider.NewRepoResolver(nil, nil, gitprovider.StaticResolver{P: fake}),
		queue, auditStore, database)

	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	gitrepos.NewHandler(svc, tenancySvc, itAuthorizer{}).RegisterRoutes(api)
	return &itFixture{srv: httptest.NewServer(router), database: database, git: fake, queue: queue, svc: svc}
}

func (f *itFixture) req(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

type repoView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Repo         string `json:"repo"`
	Scope        string `json:"scope"`
	TeamID       string `json:"teamId"`
	CommitPolicy string `json:"commitPolicy"`
	BaseBranch   string `json:"baseBranch"`
	IsDefault    bool   `json:"isDefault"`
}

// A repo slug already registered by ANOTHER org is rejected with 409
// (ErrRepoRegisteredElsewhere): webhook deliveries are routed per
// (lower(repo), provider) to a single row's secret — a slug lives in
// exactly one org.
func TestRegisterCrossOrgDuplicateConflict(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	ctx := context.Background()
	if _, err := f.database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:2','other','Other','kc-2')`); err != nil {
		t.Fatal(err)
	}
	foreign := &types.TenantGitRepo{
		OrgID: "org:2", Name: "baseline", Repo: "acme/shared",
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopePlatform, IsDefault: true,
	}
	if err := inventory.NewStore().UpsertGitRepo(ctx, f.database.Pool, foreign); err != nil {
		t.Fatal(err)
	}
	code, body := f.req(t, "POST", "/api/v1/tenants/acme/git-repos", "admin",
		`{"name":"shared","repo":"ACME/shared","scope":"platform"}`)
	if code != http.StatusConflict {
		t.Fatalf("cross-org duplicate = %d %s, want 409", code, body)
	}
}

func TestGitReposEndToEnd(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"

	// Unauthenticated → 401; outsider → 403.
	if code, _ := f.req(t, "GET", base, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("unauth: %d", code)
	}
	if code, _ := f.req(t, "GET", base, "outsider", ""); code != http.StatusForbidden {
		t.Fatalf("outsider: %d", code)
	}

	// Register the platform baseline (admin only).
	code, body := f.req(t, "POST", base, "admin", `{"name":"baseline","repo":"acme/acme-inari-state","scope":"platform","isDefault":true}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register baseline: %d %s", code, body)
	}
	var regOut struct {
		Repo repoView `json:"repo"`
	}
	if err := json.Unmarshal([]byte(body), &regOut); err != nil {
		t.Fatal(err)
	}
	baseline := regOut.Repo
	if !baseline.IsDefault || baseline.CommitPolicy != "direct" || baseline.BaseBranch != "main" {
		t.Errorf("baseline defaults: %+v", baseline)
	}

	// Devs cannot register (settings-write required).
	if code, body := f.req(t, "POST", base, "dev-a", `{"name":"x","repo":"acme/x","scope":"platform"}`); code != http.StatusForbidden {
		t.Fatalf("dev register: %d %s", code, body)
	}

	// Register team-a repo. The attach flow commits its root app into the
	// baseline repo, so the fake git host must know both repos.
	ctx := context.Background()
	if _, err := f.git.EnsureRepo(ctx, "acme/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.git.EnsureRepo(ctx, "acme/team-a-gitops"); err != nil {
		t.Fatal(err)
	}
	code, body = f.req(t, "POST", base, "admin", `{"name":"team-a-gitops","repo":"acme/team-a-gitops","scope":"team","teamId":"11111111-1111-1111-1111-111111111111"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register team repo: %d %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &regOut); err != nil {
		t.Fatal(err)
	}
	teamA := regOut.Repo

	// List: admin sees 2; dev-a sees 2 (baseline + own); dev-b sees 1.
	listRepos := func(token string) []repoView {
		code, body := f.req(t, "GET", base, token, "")
		if code != http.StatusOK {
			t.Fatalf("list %s: %d %s", token, code, body)
		}
		var out struct {
			Repos []repoView `json:"repos"`
		}
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		return out.Repos
	}
	if n := len(listRepos("admin")); n != 2 {
		t.Errorf("admin list = %d, want 2", n)
	}
	if n := len(listRepos("dev-a")); n != 2 {
		t.Errorf("dev-a list = %d, want 2", n)
	}
	if n := len(listRepos("dev-b")); n != 1 {
		t.Errorf("dev-b list = %d, want 1 (baseline only)", n)
	}

	// Get: dev-b cannot see team-a's repo (404, not 403 — no existence leak).
	if code, _ := f.req(t, "GET", base+"/"+teamA.ID, "dev-b", ""); code != http.StatusNotFound {
		t.Errorf("dev-b get team-a repo: %d, want 404", code)
	}
	// dev-a sees it, with a provider status probe.
	code, body = f.req(t, "GET", base+"/"+teamA.ID, "dev-a", "")
	if code != http.StatusOK {
		t.Fatalf("dev-a get: %d %s", code, body)
	}
	var getOut struct {
		Repo   repoView `json:"repo"`
		Status *struct {
			State string `json:"state"`
		} `json:"gitProviderStatus"`
	}
	if err := json.Unmarshal([]byte(body), &getOut); err != nil {
		t.Fatal(err)
	}
	if getOut.Status == nil || getOut.Status.State == "" {
		t.Errorf("missing provider status probe: %s", body)
	}

	// Baseline is read-visible to every org member (decision 5a): both devs
	// can GET it, but neither can write it (platform repos are
	// settings-write only).
	for _, tok := range []string{"dev-a", "dev-b"} {
		if code, body := f.req(t, "GET", base+"/"+baseline.ID, tok, ""); code != http.StatusOK {
			t.Errorf("%s get baseline: %d %s, want 200 (baseline read-all)", tok, code, body)
		}
		if code, _ := f.req(t, "PATCH", base+"/"+baseline.ID, tok, `{"commitPolicy":"direct"}`); code != http.StatusForbidden {
			t.Errorf("%s patch baseline: %d, want 403", tok, code)
		}
	}

	// PATCH: dev-a (owning team, deployments_create) may patch policy/branch.
	code, body = f.req(t, "PATCH", base+"/"+teamA.ID, "dev-a", `{"commitPolicy":"pull_request","baseBranch":"trunk"}`)
	if code != http.StatusOK {
		t.Fatalf("dev-a patch: %d %s", code, body)
	}
	// PATCH: dev-a may NOT promote to default (settings-write only).
	if code, _ := f.req(t, "PATCH", base+"/"+teamA.ID, "dev-a", `{"isDefault":true}`); code != http.StatusForbidden {
		t.Errorf("dev-a promote: %d, want 403", code)
	}
	// PATCH: explicit demote is rejected with 422.
	if code, _ := f.req(t, "PATCH", base+"/"+baseline.ID, "admin", `{"isDefault":false}`); code != http.StatusUnprocessableEntity {
		t.Errorf("demote: %d, want 422", code)
	}

	// Baseline replacement flow: register a second platform repo, promote it.
	code, body = f.req(t, "POST", base, "admin", `{"name":"baseline-2","repo":"acme/state-v2","scope":"platform"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register baseline-2: %d %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &regOut); err != nil {
		t.Fatal(err)
	}
	baseline2 := regOut.Repo
	code, body = f.req(t, "PATCH", base+"/"+baseline2.ID, "admin", `{"isDefault":true}`)
	if code != http.StatusOK {
		t.Fatalf("promote baseline-2: %d %s", code, body)
	}
	// Old default demoted.
	code, body = f.req(t, "GET", base+"/"+baseline.ID, "admin", "")
	if code != http.StatusOK {
		t.Fatal(code, body)
	}
	if err := json.Unmarshal([]byte(body), &getOut); err != nil {
		t.Fatal(err)
	}
	if getOut.Repo.IsDefault {
		t.Error("old default still flagged")
	}

	// DELETE: old default (now non-default) deletes cleanly.
	code, body = f.req(t, "DELETE", base+"/"+baseline.ID, "admin", "")
	if code != http.StatusOK {
		t.Fatalf("delete old baseline: %d %s", code, body)
	}
	// DELETE: the current default is blocked.
	if code, _ := f.req(t, "DELETE", base+"/"+baseline2.ID, "admin", ""); code != http.StatusConflict {
		t.Errorf("delete default: %d, want 409", code)
	}
	// DELETE: dev cannot delete.
	if code, _ := f.req(t, "DELETE", base+"/"+teamA.ID, "dev-a", ""); code != http.StatusForbidden {
		t.Errorf("dev delete: %d, want 403", code)
	}
	// DELETE team-a repo.
	if code, body := f.req(t, "DELETE", base+"/"+teamA.ID, "admin", ""); code != http.StatusOK {
		t.Errorf("delete team repo: %d %s", code, body)
	}
}

func TestGitRepoUnregisterGuardAndTeardown(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"
	ctx := context.Background()

	// Register a team repo and attach a managed addon + a bound-cluster
	// instance to it.
	code, body := f.req(t, "POST", base, "admin", `{"name":"team-a","repo":"acme/team-a","scope":"team","teamId":"11111111-1111-1111-1111-111111111111"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register: %d %s", code, body)
	}
	var regOut struct {
		Repo repoView `json:"repo"`
	}
	if err := json.Unmarshal([]byte(body), &regOut); err != nil {
		t.Fatal(err)
	}
	repoID := regOut.Repo.ID

	store := inventory.NewStore()
	if _, err := f.database.Pool.Exec(ctx, `UPDATE clusters SET baseline_repo_id = $1 WHERE id = 'cluster-1'`, repoID); err == nil {
		// cluster-1 bound directly (team scope would fail BindClusterBaseline;
		// direct SQL is fine for guard testing).
	}
	if err := store.Create(ctx, f.database.Pool, &types.ResourceInstance{
		ID: "inst-1", OrgID: "org:1", ClusterID: "cluster-1", CatalogItemID: "platform:cert-manager",
		Version: "v1", Spec: json.RawMessage(`{}`), State: "running", ManagementMode: "adopt",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertClusterAddon(ctx, f.database.Pool, &types.ClusterAddon{
		OrgID: "org:1", ClusterID: "cluster-1", CatalogItem: "platform:cert-manager",
		State: types.AddonStateManaged, RepoID: repoID, RepoPath: "addons/cert-manager",
		ArgoCDApp: "inari-addon-x",
		Source:    types.SourceDescriptor{Kind: types.SourceKindHelm},
	}); err != nil {
		t.Fatal(err)
	}

	// Unforced delete: 409 with affected-workload counts.
	code, body = f.req(t, "DELETE", base+"/"+repoID, "admin", "")
	if code != http.StatusConflict {
		t.Fatalf("unforced delete: %d %s, want 409", code, body)
	}
	if !strings.Contains(body, "instances=") {
		t.Errorf("409 body lacks ref counts: %s", body)
	}

	// Bad mode: 422.
	if code, _ := f.req(t, "DELETE", base+"/"+repoID+"?force=true&mode=bogus", "admin", ""); code != http.StatusUnprocessableEntity {
		t.Errorf("bad mode: %d, want 422", code)
	}

	// Teardown: manifests deleted from the repo, app deletion enqueued.
	if _, err := f.git.EnsureRepo(ctx, "acme/team-a"); err != nil {
		t.Fatal(err)
	}
	code, body = f.req(t, "DELETE", base+"/"+repoID+"?force=true&mode=teardown", "admin", "")
	if code != http.StatusOK {
		t.Fatalf("teardown: %d %s", code, body)
	}
	if len(f.git.Deletions) != 1 {
		t.Fatalf("git deletions = %d, want 1", len(f.git.Deletions))
	}
	paths := f.git.Deletions[0].Paths
	joined := strings.Join(paths, ",")
	if !strings.Contains(joined, "addons/cert-manager") || !strings.Contains(joined, "clusters/cluster-1/") {
		t.Errorf("teardown paths = %v", paths)
	}
	if len(f.queue.cmds) != 2 {
		t.Errorf("agent app deletions = %d, want 2 (instance + addon)", len(f.queue.cmds))
	}

	// Row gone.
	if code, _ := f.req(t, "GET", base+"/"+repoID, "admin", ""); code != http.StatusNotFound {
		t.Errorf("get after teardown: %d, want 404", code)
	}
}

// TestForceDeleteOrphanMode pins the orphan path over HTTP (decision 6):
// the row is unregistered, repo content is untouched, no agent commands are
// enqueued, and instance references are nulled by the FK (SET NULL).
func TestForceDeleteOrphanMode(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"
	ctx := context.Background()

	code, body := f.req(t, "POST", base, "admin", `{"name":"team-a","repo":"acme/team-a","scope":"team","teamId":"11111111-1111-1111-1111-111111111111"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("register: %d %s", code, body)
	}
	var regOut struct {
		Repo repoView `json:"repo"`
	}
	if err := json.Unmarshal([]byte(body), &regOut); err != nil {
		t.Fatal(err)
	}
	repoID := regOut.Repo.ID

	store := inventory.NewStore()
	if err := store.Create(ctx, f.database.Pool, &types.ResourceInstance{
		ID: "inst-orphan", OrgID: "org:1", ClusterID: "cluster-1", CatalogItemID: "platform:cert-manager",
		Version: "v1", Spec: json.RawMessage(`{}`), State: "running", ManagementMode: "adopt",
		RepoID: repoID,
	}); err != nil {
		t.Fatal(err)
	}

	// Blocked without force (409 with ref counts in the message).
	code, body = f.req(t, "DELETE", base+"/"+repoID, "admin", "")
	if code != http.StatusConflict {
		t.Fatalf("unforced delete: %d %s, want 409", code, body)
	}
	if !strings.Contains(body, "instances=1") {
		t.Errorf("409 body lacks instance count: %s", body)
	}

	// Forced orphan: row gone, no git deletions, no agent commands, the
	// instance's repo_id is NULLed by the FK.
	code, body = f.req(t, "DELETE", base+"/"+repoID+"?force=true&mode=orphan", "admin", "")
	if code != http.StatusOK {
		t.Fatalf("orphan delete: %d %s", code, body)
	}
	if len(f.git.Deletions) != 0 {
		t.Errorf("orphan mode deleted repo content: %v", f.git.Deletions)
	}
	if len(f.queue.cmds) != 0 {
		t.Errorf("orphan mode enqueued agent commands: %v", f.queue.cmds)
	}
	var orphaned *string
	if err := f.database.Pool.QueryRow(ctx,
		`SELECT repo_id FROM resource_instances WHERE id = 'inst-orphan'`).Scan(&orphaned); err != nil {
		t.Fatal(err)
	}
	if orphaned != nil {
		t.Errorf("instance repo_id = %v, want NULL after orphan", *orphaned)
	}
	if code, _ := f.req(t, "GET", base+"/"+repoID, "admin", ""); code != http.StatusNotFound {
		t.Errorf("get after orphan: %d, want 404", code)
	}
}

func TestGitRepoRegisterValidation(t *testing.T) {
	f := newITServer(t)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/git-repos"

	cases := []struct {
		name string
		body string
		want int
	}{
		{"unsupported provider", `{"name":"x","repo":"acme/x","provider":"gitlab"}`, http.StatusUnprocessableEntity},
		{"bad repo slug", `{"name":"x","repo":"noslash"}`, http.StatusUnprocessableEntity},
		{"team scope without team", `{"name":"x","repo":"acme/x","scope":"team"}`, http.StatusUnprocessableEntity},
		{"platform with team", `{"name":"x","repo":"acme/x","scope":"platform","teamId":"11111111-1111-1111-1111-111111111111"}`, http.StatusUnprocessableEntity},
		{"cross-org team", `{"name":"x","repo":"acme/x","scope":"team","teamId":"99999999-9999-9999-9999-999999999999"}`, http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, body := f.req(t, "POST", base, "admin", tc.body); code != tc.want {
				t.Errorf("%d %s, want %d", code, body, tc.want)
			}
		})
	}

	// Duplicate repo under a different name: 409.
	if code, _ := f.req(t, "POST", base, "admin", `{"name":"one","repo":"acme/dup","scope":"platform"}`); code != http.StatusOK && code != http.StatusCreated {
		t.Fatal(code)
	}
	if code, body := f.req(t, "POST", base, "admin", `{"name":"two","repo":"acme/dup","scope":"platform"}`); code != http.StatusConflict {
		t.Errorf("duplicate: %d %s, want 409", code, body)
	}
}
