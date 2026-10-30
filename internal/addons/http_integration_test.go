//go:build integration

// HTTP integration tests for the addons REST surface: authn/authz mapping,
// validation errors, team filtering, and the adopt → update → enable-prune
// CD loop over the fake git provider.
package addons_test

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

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/addons"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "admin":
		return &authn.Identity{Subject: "admin-1", Organizations: []string{"acme"}}, nil
	case "dev-a":
		return &authn.Identity{Subject: "dev-a1", Organizations: []string{"acme"}, Groups: []string{"/tenant-acme/team-a"}}, nil
	case "dev-b":
		return &authn.Identity{Subject: "dev-b1", Organizations: []string{"acme"}, Groups: []string{"/tenant-acme/team-b"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "x", Organizations: []string{"other"}}, nil
	}
	return nil, errors.New("invalid token")
}

type itAuthorizer struct{}

func (itAuthorizer) Check(_ context.Context, user, relation, _ string) (bool, error) {
	switch user {
	case "user:admin-1":
		return true, nil
	case "user:dev-a1", "user:dev-b1":
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

type repoGetterAdapter struct {
	s  *inventory.Store
	db *db.DB
}

func (a repoGetterAdapter) GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	return a.s.GetGitRepo(ctx, a.db.Pool, orgID, id)
}

func (a repoGetterAdapter) GetDefaultGitRepo(ctx context.Context, orgID string) (*types.TenantGitRepo, error) {
	return a.s.GetDefaultGitRepo(ctx, a.db.Pool, orgID)
}

type itFixture struct {
	srv      *httptest.Server
	database *db.DB
	git      *gitprovider.Fake
	queue    *itQueue
	svc      *addons.Service
	inv      *inventory.Service
	audit    *audit.Store
}

func newITServer(t *testing.T, policy types.CommitPolicy) *itFixture {
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
		INSERT INTO clusters (id, org_id, name, labels, state) VALUES
		  ('cluster-1','org:1','prod-eu','{"env":"prod"}','active'),
		  ('cluster-2','org:1','prod-us','{"env":"prod"}','active');`
	if _, err := database.Pool.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}

	auditStore := audit.NewStore()
	tenancySvc := tenancy.NewService(database, nil, tenancy.NewStore(), auditStore)
	invStore := inventory.NewStore()
	catSvc := catalog.NewService(database, catalog.NewStore(), nil, auditStore, nil)
	if err := catSvc.SeedPlatformApps(ctx); err != nil {
		t.Fatal(err)
	}
	fake := gitprovider.NewFake()
	queue := &itQueue{}
	resolver := gitprovider.NewRepoResolver(repoGetterAdapter{invStore, database}, nil, gitprovider.StaticResolver{P: fake})
	svc := addons.NewService(database, invStore, catSvc, clusterListerAdapter{invStore, database}, resolver, queue, auditStore)

	// The baseline repo the adopt defaults to (registered directly through
	// the store — registration itself is the gitrepos module's surface).
	baseline := &types.TenantGitRepo{
		OrgID: "org:1", Name: "baseline", Repo: "acme/acme-inari-state",
		Scope: types.GitRepoScopePlatform, CommitPolicy: policy, BaseBranch: "main", IsDefault: true,
	}
	if err := invStore.UpsertGitRepo(ctx, database.Pool, baseline); err != nil {
		t.Fatal(err)
	}
	// A team repo for the write-enforcement/team-filtering assertions.
	teamRepo := &types.TenantGitRepo{
		OrgID: "org:1", Name: "team-a", Repo: "acme/team-a-gitops",
		Scope: types.GitRepoScopeTeam, TeamID: "11111111-1111-1111-1111-111111111111",
		CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
	}
	if err := invStore.UpsertGitRepo(ctx, database.Pool, teamRepo); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.EnsureRepo(ctx, "acme/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.EnsureRepo(ctx, "acme/team-a-gitops"); err != nil {
		t.Fatal(err)
	}

	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	addons.NewHandler(svc, tenancySvc, itAuthorizer{}).
		WithRepoWriteEnforcement(tenancySvc, repoGetterAdapter{invStore, database}).
		RegisterRoutes(api)
	return &itFixture{
		srv: httptest.NewServer(router), database: database, git: fake, queue: queue,
		svc: svc, inv: inventory.NewService(database, invStore, auditStore, nil), audit: auditStore,
	}
}

// clusterListerAdapter serves the addons ClusterLister seam from the DB.
type clusterListerAdapter struct {
	s  *inventory.Store
	db *db.DB
}

func (l clusterListerAdapter) GetCluster(ctx context.Context, id string) (*types.Cluster, error) {
	var c types.Cluster
	var labels []byte
	err := l.db.Pool.QueryRow(ctx,
		`SELECT id, org_id, name, state, COALESCE(labels::text,'{}') FROM clusters WHERE id = $1`, id).
		Scan(&c.ID, &c.OrgID, &c.Name, &c.State, &labels)
	if errors.Is(err, pgx.ErrNoRows) {
		// Mirror the production clusterregistry.Service contract.
		return nil, clusterregistry.ErrClusterNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(labels, &c.Labels)
	return &c, nil
}

func (l clusterListerAdapter) ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error) {
	rows, err := l.db.Pool.Query(ctx,
		`SELECT id, org_id, name, state, COALESCE(labels::text,'{}') FROM clusters WHERE org_id = $1 ORDER BY id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Cluster
	for rows.Next() {
		var c types.Cluster
		var labels []byte
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Name, &c.State, &labels); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(labels, &c.Labels)
		out = append(out, c)
	}
	return out, rows.Err()
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

type addonView struct {
	ID                string   `json:"id"`
	CatalogItem       string   `json:"catalogItem"`
	State             string   `json:"state"`
	DeployMode        string   `json:"deployMode"`
	RepoID            string   `json:"repoId"`
	RepoPath          string   `json:"repoPath"`
	ChartVersion      string   `json:"chartVersion"`
	ArgoCDApp         string   `json:"argocdApp"`
	PruneEnabled      bool     `json:"pruneEnabled"`
	AvailableVersions []string `json:"availableVersions"`
}

// teamRepoID resolves the fixture's team-a repo row ID.
func (f *itFixture) teamRepoID(t *testing.T) string {
	t.Helper()
	var id string
	if err := f.database.Pool.QueryRow(t.Context(),
		`SELECT id FROM tenant_git_repos WHERE org_id = 'org:1' AND name = 'team-a'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAddonsHTTPEndToEnd(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/clusters/cluster-1/addons"

	// Authn/authz gates.
	if code, _ := f.req(t, "GET", base, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("unauth: %d", code)
	}
	if code, _ := f.req(t, "GET", base, "outsider", ""); code != http.StatusForbidden {
		t.Fatalf("outsider: %d", code)
	}

	// Empty list.
	code, body := f.req(t, "GET", base, "admin", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	var listOut struct {
		Addons []addonView `json:"addons"`
	}
	if err := json.Unmarshal([]byte(body), &listOut); err != nil || len(listOut.Addons) != 0 {
		t.Fatalf("empty list: %s", body)
	}

	// Adopt: schema-invalid values → 422 with field errors.
	code, body = f.req(t, "POST", base+"/platform:cert-manager/adopt", "admin",
		`{"version":"v1.16.1","values":{"replicaCount":0}}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid values: %d %s", code, body)
	}

	// Unknown catalog item → 404; unknown version → 404.
	if code, _ := f.req(t, "POST", base+"/platform:missing/adopt", "admin", `{}`); code != http.StatusNotFound {
		t.Fatalf("unknown item: %d", code)
	}
	if code, _ := f.req(t, "POST", base+"/platform:cert-manager/adopt", "admin", `{"version":"v9.9.9"}`); code != http.StatusNotFound {
		t.Fatalf("unknown version: %d", code)
	}

	// Valid adopt (application mode, default baseline repo).
	code, body = f.req(t, "POST", base+"/platform:cert-manager/adopt", "admin",
		`{"version":"v1.16.1","values":{"crds":{"enabled":true}}}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("adopt: %d %s", code, body)
	}
	var adoptOut struct {
		Addon     addonView `json:"addon"`
		CommitSHA string    `json:"commitSha"`
		PRURL     string    `json:"prUrl"`
	}
	if err := json.Unmarshal([]byte(body), &adoptOut); err != nil {
		t.Fatal(err)
	}
	if adoptOut.Addon.State != "managed" || adoptOut.CommitSHA == "" || adoptOut.PRURL != "" {
		t.Errorf("adopt result: %s", body)
	}
	addonID := adoptOut.Addon.ID
	if adoptOut.Addon.ArgoCDApp != "inari-addon-"+strings.ToLower(addonID) {
		t.Errorf("argocdApp = %q", adoptOut.Addon.ArgoCDApp)
	}

	// Re-adopt → 409.
	if code, _ := f.req(t, "POST", base+"/platform:cert-manager/adopt", "admin", `{}`); code != http.StatusConflict {
		t.Fatalf("re-adopt: %d", code)
	}

	// List shows the managed addon with the catalog version dropdown data.
	code, body = f.req(t, "GET", base, "admin", "")
	if err := json.Unmarshal([]byte(body), &listOut); err != nil || len(listOut.Addons) != 1 {
		t.Fatalf("list after adopt: %d %s", code, body)
	}
	if len(listOut.Addons[0].AvailableVersions) != 2 {
		t.Errorf("availableVersions = %v", listOut.Addons[0].AvailableVersions)
	}

	// PATCH update: version bump + values.
	code, body = f.req(t, "PATCH", "/api/v1/tenants/acme/addons/"+addonID, "admin",
		`{"chartVersion":"v1.16.2","values":{"crds":{"enabled":false}}}`)
	if code != http.StatusOK {
		t.Fatalf("update: %d %s", code, body)
	}
	if !strings.Contains(f.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/application.yaml"], "targetRevision: v1.16.2") {
		t.Error("committed application must pin the new version")
	}

	// Empty PATCH → 422.
	if code, _ := f.req(t, "PATCH", "/api/v1/tenants/acme/addons/"+addonID, "admin", `{}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("empty patch: %d", code)
	}

	// Enable prune → 200 + prune in git; repeat → 409.
	if code, body = f.req(t, "POST", "/api/v1/tenants/acme/addons/"+addonID+"/enable-prune", "admin", ""); code != http.StatusOK {
		t.Fatalf("enable-prune: %d %s", code, body)
	}
	if !strings.Contains(f.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/application.yaml"], "prune: true") {
		t.Error("enable-prune must commit prune: true")
	}
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/addons/"+addonID+"/enable-prune", "admin", ""); code != http.StatusConflict {
		t.Fatalf("repeat enable-prune: %d", code)
	}

	// Unknown addon → 404.
	if code, _ := f.req(t, "PATCH", "/api/v1/tenants/acme/addons/nope", "admin", `{"chartVersion":"v1"}`); code != http.StatusNotFound {
		t.Fatalf("unknown addon: %d", code)
	}
}

func TestAddonsHTTPTeamEnforcement(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/clusters/cluster-1/addons"

	// dev-a (team-a member, deployments_create) may adopt into team-a's repo.
	code, body := f.req(t, "POST", base+"/platform:external-secrets/adopt", "dev-a",
		`{"version":"v0.12.1","repoId":"`+repoIDOf(t, f, "team-a")+`"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("team-a adopt: %d %s", code, body)
	}
	var out struct {
		Addon addonView `json:"addon"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}

	// dev-b (team-b member) may NOT write team-a's repo.
	if code, _ := f.req(t, "POST", base+"/platform:cert-manager/adopt", "dev-b",
		`{"version":"v1.16.1","repoId":"`+repoIDOf(t, f, "team-a")+`"}`); code != http.StatusForbidden {
		t.Fatalf("cross-team adopt: %d", code)
	}

	// dev-b does not see team-a's managed addon; admin does.
	var listOut struct {
		Addons []addonView `json:"addons"`
	}
	_, body = f.req(t, "GET", base, "dev-b", "")
	if err := json.Unmarshal([]byte(body), &listOut); err != nil {
		t.Fatal(err)
	}
	for _, a := range listOut.Addons {
		if a.RepoPath == "addons/external-secrets" {
			t.Errorf("dev-b must not see team-a's addon: %s", body)
		}
	}
	_, body = f.req(t, "GET", base, "admin", "")
	if err := json.Unmarshal([]byte(body), &listOut); err != nil || len(listOut.Addons) == 0 {
		t.Fatalf("admin list: %s", body)
	}

	// dev-b may not mutate team-a's addon (recorded-repo enforcement).
	if code, _ := f.req(t, "PATCH", "/api/v1/tenants/acme/addons/"+out.Addon.ID, "dev-b",
		`{"chartVersion":"v0.12.1"}`); code != http.StatusForbidden {
		t.Fatalf("cross-team patch: %d", code)
	}
}

func TestAddonsHTTPPullRequestPolicy(t *testing.T) {
	f := newITServer(t, types.CommitPolicyPullRequest)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/clusters/cluster-2/addons"

	code, body := f.req(t, "POST", base+"/platform:cert-manager/adopt", "admin", `{"version":"v1.16.1"}`)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("adopt: %d %s", code, body)
	}
	var out struct {
		PRURL string `json:"prUrl"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.PRURL == "" {
		t.Fatalf("PR adopt: %s", body)
	}
	if len(f.queue.cmds) != 0 {
		t.Error("registration waits for the PR merge")
	}
}

// TestAddonsHTTPSupportedAddonsCDLoop is the operator-sunset Phase 1
// addons-track exit criterion: cert-manager, ExternalDNS, and ArgoCD are
// registered first-class addons — the adopt → update CD loop works for all
// three across both deploy modes, and schema-invalid values are rejected
// with 422 field-level errors before anything is committed or registered.
func TestAddonsHTTPSupportedAddonsCDLoop(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	base := "/api/v1/tenants/acme/clusters/cluster-1/addons"

	// Schema rejection (decision 4): bad values for each addon fail with 422
	// field-level errors and no side effects.
	rejections := []struct {
		item, version, values, wantPath string
	}{
		{"platform:cert-manager", "v1.16.2", `{"replicaCount":0}`, "/replicaCount"},
		{"platform:external-dns", "1.15.2", `{"policy":"delete-everything"}`, "/policy"},
		{"platform:argocd", "7.6.12", `{"server":{"replicas":0}}`, "/server/replicas"},
	}
	for _, r := range rejections {
		code, body := f.req(t, "POST", base+"/"+r.item+"/adopt", "admin",
			`{"version":"`+r.version+`","values":`+r.values+`}`)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("%s adopt with bad values: got %d (%s), want 422", r.item, code, body)
			continue
		}
		if !strings.Contains(body, r.wantPath) {
			t.Errorf("%s 422 body %s lacks field path %s", r.item, body, r.wantPath)
		}
	}
	if files := f.git.Files("acme/acme-inari-state", "main"); len(files) != 0 {
		t.Fatalf("rejected adopts committed files: %v", files)
	}

	// Adopt + update CD loop: external-dns as a single-cluster Application,
	// argocd fleet-wide as an ApplicationSet (cert-manager is covered by
	// TestAddonsHTTPEndToEnd).
	cases := []struct {
		item       string
		version    string
		values     string
		newValues  string
		wantInFile string
		deployMode string
		wantPath   string
		wantFile   string
	}{
		{
			item: "platform:external-dns", version: "1.15.2",
			values: `{"policy":"upsert-only"}`, newValues: `{"policy":"sync"}`,
			wantInFile: "policy: sync",
			deployMode: "application", wantPath: "addons/external-dns",
			wantFile: "addons/external-dns/application.yaml",
		},
		{
			item: "platform:argocd", version: "7.6.12",
			values: `{"server":{"replicas":2}}`, newValues: `{"server":{"replicas":3}}`,
			wantInFile: "replicas: 3",
			deployMode: "applicationset", wantPath: "addons/argocd",
			wantFile: "addons/argocd/applicationset.yaml",
		},
	}
	for _, c := range cases {
		body := `{"version":"` + c.version + `","values":` + c.values
		if c.deployMode == "applicationset" {
			body += `,"deployMode":"applicationset","clusterSelector":{"env":"prod"}`
		}
		body += `}`
		code, respBody := f.req(t, "POST", base+"/"+c.item+"/adopt", "admin", body)
		if code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("%s adopt: %d %s", c.item, code, respBody)
		}
		var out struct {
			Addon     addonView `json:"addon"`
			CommitSHA string    `json:"commitSha"`
		}
		if err := json.Unmarshal([]byte(respBody), &out); err != nil {
			t.Fatal(err)
		}
		if out.Addon.State != "managed" || out.CommitSHA == "" {
			t.Errorf("%s adopt result: %s", c.item, respBody)
		}
		if out.Addon.DeployMode != c.deployMode {
			t.Errorf("%s deployMode = %q, want %q", c.item, out.Addon.DeployMode, c.deployMode)
		}
		if !strings.Contains(out.Addon.RepoPath, c.wantPath) {
			t.Errorf("%s repoPath = %q, want under %s", c.item, out.Addon.RepoPath, c.wantPath)
		}
		appFile := f.git.Files("acme/acme-inari-state", "main")[c.wantFile]
		if !strings.Contains(appFile, "targetRevision: "+c.version) {
			t.Errorf("%s committed app must pin %s:\n%s", c.item, c.version, appFile)
		}

		// Update: values change re-renders and commits (the CD loop); a
		// schema-invalid update is rejected 422 with state preserved.
		code, respBody = f.req(t, "PATCH", "/api/v1/tenants/acme/addons/"+out.Addon.ID, "admin",
			`{"values":`+c.newValues+`}`)
		if code != http.StatusOK {
			t.Fatalf("%s update: %d %s", c.item, code, respBody)
		}
		// The fake provider's SHA is file-count-derived, so assert the CD
		// loop on the committed content instead.
		valuesFile := f.git.Files("acme/acme-inari-state", "main")[c.wantPath+"/values.yaml"]
		if !strings.Contains(valuesFile, c.wantInFile) {
			t.Errorf("%s update did not commit the new values (%q missing):\n%s", c.item, c.wantInFile, valuesFile)
		}
		bad := `{"policy":"bogus"}`
		if c.item == "platform:argocd" {
			bad = `{"server":{"replicas":-1}}`
		}
		if code, respBody := f.req(t, "PATCH", "/api/v1/tenants/acme/addons/"+out.Addon.ID, "admin",
			`{"values":`+bad+`}`); code != http.StatusUnprocessableEntity {
			t.Errorf("%s update with bad values: got %d (%s), want 422", c.item, code, respBody)
		}
	}

	// Fleet row: visible from both matched clusters, ApplicationSet rendered
	// with the list generator targeting cluster-1 and cluster-2.
	for _, cluster := range []string{"cluster-1", "cluster-2"} {
		_, body := f.req(t, "GET", "/api/v1/tenants/acme/clusters/"+cluster+"/addons", "admin", "")
		if !strings.Contains(body, "platform:argocd") {
			t.Errorf("%s list lacks the fleet argocd addon: %s", cluster, body)
		}
	}
	appSet := f.git.Files("acme/acme-inari-state", "main")["addons/argocd/applicationset.yaml"]
	for _, cluster := range []string{"prod-eu", "prod-us"} {
		if !strings.Contains(appSet, cluster) {
			t.Errorf("ApplicationSet list generator must target %s:\n%s", cluster, appSet)
		}
	}
}

func repoIDOf(t *testing.T, f *itFixture, name string) string {
	t.Helper()
	var id string
	if err := f.database.Pool.QueryRow(context.Background(),
		`SELECT id FROM tenant_git_repos WHERE org_id = 'org:1' AND name = $1`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
