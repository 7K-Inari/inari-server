//go:build integration

package orchestrator_test

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

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "good":
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}, nil
	case "peer":
		return &authn.Identity{Subject: "user-2", Organizations: []string{"acme"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "user-9", Organizations: []string{"other"}}, nil
	}
	return nil, errors.New("invalid token")
}

type itAuthorizer struct{ allow bool }

func (a itAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return a.allow, nil
}
func (a itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenants map[string]*types.Organization

func (t itTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := t[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

// itQueue captures enqueued agent commands.
type itQueue struct{ cmds []types.AgentCommand }

func (q *itQueue) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	q.cmds = append(q.cmds, *cmd)
	return nil
}

// itClusters resolves the seeded cluster.
type itClusters struct{}

func (itClusters) GetCluster(_ context.Context, id string) (*types.Cluster, error) {
	if id == "cluster-1" {
		return &types.Cluster{ID: "cluster-1", OrgID: "org:1", Name: "kind-dev", State: types.ClusterStateActive}, nil
	}
	return nil, errors.New("unknown cluster")
}

func itServer(t *testing.T) (*httptest.Server, *db.DB, *gitprovider.Fake, *itQueue) {
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
	seed := `
		INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1');
		INSERT INTO users (id, email) VALUES ('user-1','a@x.io'), ('user-2','b@x.io');
		INSERT INTO memberships (user_id, org_id, role) VALUES
		  ('user-1','org:1','developer'), ('user-2','org:1','platform-engineer');
		INSERT INTO clusters (id, org_id, name, state) VALUES ('cluster-1','org:1','kind-dev','active');
		INSERT INTO tenant_git_configs (org_id, repo, commit_policy, base_branch)
		  VALUES ('org:1','inari-dev/acme-inari-state','direct','main');`
	if _, err := database.Pool.Exec(ctx, seed); err != nil {
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
	fake := gitprovider.NewFake()
	git := gitprovider.StaticResolver{P: fake}
	queue := &itQueue{}
	orchSvc := orchestrator.NewService(database, inventory.NewStore(), catalogSvc, itClusters{},
		approvalsSvc, queue, git, auditStore)

	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	catalog.NewHandler(catalogSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	approvals.NewHandler(approvalsSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	inventory.NewHandler(inventorySvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	orchestrator.NewHandler(orchSvc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itAuthorizer{allow: true}).RegisterRoutes(api)
	return httptest.NewServer(router), database, fake, queue
}

func itReq(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
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

// TestCatalogListAndPin covers sync → list (visibility) → pin resolution.
func TestCatalogListAndPin(t *testing.T) {
	srv, _, _, _ := itServer(t)
	defer srv.Close()

	code, body := itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog", "good", "")
	if code != http.StatusOK {
		t.Fatalf("list catalog: %d %s", code, body)
	}
	var out struct {
		Items []catalog.ItemView `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	var pg *catalog.ItemView
	for i := range out.Items {
		if out.Items[i].ID == "curated:postgres-aws" {
			pg = &out.Items[i]
		}
	}
	if pg == nil {
		t.Fatalf("curated:postgres-aws missing from catalog: %s", body)
	}
	if len(pg.Versions) != 2 {
		t.Errorf("postgres-aws versions = %d, want 2", len(pg.Versions))
	}

	if code, body := itReq(t, srv, "PUT", "/api/v1/tenants/acme/catalog/curated:postgres-aws/pin", "good", `{"version":"1.0.0"}`); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("pin: %d %s", code, body)
	}
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog/curated:postgres-aws", "good", "")
	if code != http.StatusOK {
		t.Fatalf("get item: %d %s", code, body)
	}
	var detail struct {
		Item catalog.ItemView `json:"item"`
	}
	if err := json.Unmarshal([]byte(body), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Item.PinnedVersion != "1.0.0" {
		t.Errorf("pinnedVersion = %q, want 1.0.0", detail.Item.PinnedVersion)
	}

	// Pin to a nonexistent version is rejected.
	if code, _ := itReq(t, srv, "PUT", "/api/v1/tenants/acme/catalog/curated:postgres-aws/pin", "good", `{"version":"9.9.9"}`); code != http.StatusBadRequest {
		t.Errorf("pin bogus version: got %d, want 400", code)
	}
	// Outsider sees nothing.
	if code, _ := itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog", "outsider", ""); code != http.StatusForbidden {
		t.Errorf("outsider: got %d, want 403", code)
	}
}

// TestDeployToHealthVisible is the M2 acceptance path: deploy → commit in
// the tenant state repo → register-argocd-app enqueued → status-update makes
// health visible via the inventory API; badge + diff data served.
func TestDeployToHealthVisible(t *testing.T) {
	srv, database, git, queue := itServer(t)
	defer srv.Close()
	ctx := context.Background()

	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"my-db","namespace":"apps","ownerTeam":"developers","spec":{"engineVersion":"16","storageGB":50}}`)
	if code != http.StatusOK {
		t.Fatalf("deploy: %d %s", code, body)
	}
	var deployOut struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &deployOut); err != nil {
		t.Fatal(err)
	}
	d := deployOut.Deploy
	if d.Status != "deploying" || d.InstanceID != "my-db" || d.CommitSHA == "" {
		t.Errorf("unexpected deploy result: %+v", d)
	}

	// Commit landed in the tenant state repo.
	files := git.Files("inari-dev/acme-inari-state", "main")
	inst, ok := files["clusters/cluster-1/postgres-aws/my-db/instance.yaml"]
	if !ok {
		t.Fatalf("instance manifest not committed: %v", keysOf(files))
	}
	if !strings.Contains(inst, "kind: PostgresAWS") || !strings.Contains(inst, "storageGB: 50") {
		t.Errorf("rendered manifest wrong:\n%s", inst)
	}
	if _, ok := files["clusters/cluster-1/postgres-aws/my-db/application.yaml"]; !ok {
		t.Error("application manifest not committed")
	}

	// register-argocd-app was dispatched.
	if len(queue.cmds) != 1 {
		t.Fatalf("queued commands = %d, want 1", len(queue.cmds))
	}
	if queue.cmds[0].Type != "register-argocd-app" && !strings.Contains(queue.cmds[0].Type, "register") {
		t.Errorf("command type = %q", queue.cmds[0].Type)
	}

	// Simulate the agent's status-update.
	inv := inventory.NewService(database, inventory.NewStore(), audit.NewStore(), nil)
	matched, err := inv.ApplyStatus(ctx, "cluster-1", inventory.StatusUpdate{
		Resource: types.ResourceRef{Kind: "PostgresAWS", Name: "my-db", Namespace: "apps"},
		Health:   "healthy", Sync: "synced",
	})
	if err != nil || !matched {
		t.Fatalf("apply status: matched=%v err=%v", matched, err)
	}

	// Health is visible via the inventory API, with the version badge.
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/instances/my-db", "good", "")
	if code != http.StatusOK {
		t.Fatalf("get instance: %d %s", code, body)
	}
	var instOut struct {
		Instance inventory.InstanceView `json:"instance"`
	}
	if err := json.Unmarshal([]byte(body), &instOut); err != nil {
		t.Fatal(err)
	}
	got := instOut.Instance
	if got.Health != "healthy" || got.State != types.InstanceStateRunning {
		t.Errorf("health=%q state=%q", got.Health, got.State)
	}
	if got.LatestVersion != "1.1.0" || got.NewVersionAvailable {
		t.Errorf("badge: latest=%q new=%v (deployed 1.1.0 = latest, so no badge)", got.LatestVersion, got.NewVersionAvailable)
	}

	// Diff preview data for the upgrade.
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/instances/my-db/diff?to=1.1.0", "good", "")
	if code != http.StatusOK {
		t.Fatalf("diff: %d %s", code, body)
	}
	var diffOut struct {
		Diff orchestrator.DiffPreview `json:"diff"`
	}
	if err := json.Unmarshal([]byte(body), &diffOut); err != nil {
		t.Fatal(err)
	}
	if diffOut.Diff.CurrentVersion != "1.1.0" || diffOut.Diff.TargetVersion != "1.1.0" {
		t.Errorf("diff versions: %+v", diffOut.Diff)
	}
	if diffOut.Diff.CurrentManifest == "" || diffOut.Diff.TargetManifest == "" {
		t.Error("diff manifests empty")
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestApprovalGate covers the peer-approval flow: deploy is held, self-approval
// is rejected, a platform-engineer peer approves, then deploy proceeds.
func TestApprovalGate(t *testing.T) {
	srv, database, _, _ := itServer(t)
	defer srv.Close()
	ctx := context.Background()

	// Flip the item to peer approval.
	if _, err := database.Pool.Exec(ctx,
		`UPDATE catalog_items SET approval_policy = 'peer' WHERE id = 'curated:web-service'`); err != nil {
		t.Fatal(err)
	}

	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"curated:web-service","clusterId":"cluster-1","name":"web","channel":"incubating","spec":{"hostname":"app.example.com"}}`)
	if code != http.StatusOK {
		t.Fatalf("deploy: %d %s", code, body)
	}
	var out struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Deploy.Status != "pending_approval" || out.Deploy.ApprovalID == "" {
		t.Fatalf("expected pending_approval, got %+v", out.Deploy)
	}

	// Requester cannot self-approve.
	code, _ = itReq(t, srv, "POST", "/api/v1/tenants/acme/approvals/"+out.Deploy.ApprovalID+"/decide", "good", `{"approve":true}`)
	if code != http.StatusForbidden {
		t.Errorf("self-approve: got %d, want 403", code)
	}

	// A platform-engineer peer approves.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/approvals/"+out.Deploy.ApprovalID+"/decide", "peer", `{"approve":true}`)
	if code != http.StatusOK {
		t.Fatalf("peer approve: %d %s", code, body)
	}
	var decided struct {
		Approval types.ApprovalRequest `json:"approval"`
	}
	if err := json.Unmarshal([]byte(body), &decided); err != nil {
		t.Fatal(err)
	}
	if decided.Approval.State != types.ApprovalStateApproved || decided.Approval.Approver != "user-2" {
		t.Errorf("decided = %+v", decided.Approval)
	}

	// Pending list is now empty.
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/approvals?state=pending", "good", "")
	if code != http.StatusOK {
		t.Fatalf("list approvals: %d", code)
	}
	if strings.Contains(body, out.Deploy.ApprovalID) {
		t.Error("approved request still listed as pending")
	}
}

// TestUpgradeFlow covers one-click upgrade through the orchestrator path.
func TestUpgradeFlow(t *testing.T) {
	srv, database, git, queue := itServer(t)
	defer srv.Close()

	// Pin the tenant to 1.0.0 so the deploy starts behind latest.
	if code, body := itReq(t, srv, "PUT", "/api/v1/tenants/acme/catalog/curated:postgres-aws/pin", "good", `{"version":"1.0.0"}`); code >= 300 {
		t.Fatalf("pin: %d %s", code, body)
	}
	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/deploys", "good",
		`{"itemId":"curated:postgres-aws","clusterId":"cluster-1","name":"db1","spec":{"storageGB":20}}`)
	if code != http.StatusOK {
		t.Fatalf("deploy: %d %s", code, body)
	}
	var out struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Deploy.Version != "1.0.0" {
		t.Fatalf("pinned deploy version = %q, want 1.0.0", out.Deploy.Version)
	}

	// Badge reports the newer version.
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/instances/db1", "good", "")
	if code != http.StatusOK {
		t.Fatalf("get: %d %s", code, body)
	}
	var instOut struct {
		Instance inventory.InstanceView `json:"instance"`
	}
	if err := json.Unmarshal([]byte(body), &instOut); err != nil {
		t.Fatal(err)
	}
	if instOut.Instance.LatestVersion != "1.1.0" || !instOut.Instance.NewVersionAvailable {
		t.Errorf("badge = %+v", instOut.Instance)
	}

	// One-click upgrade (explicit version bypasses the pin).
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/instances/db1/upgrade", "good", `{"toVersion":"1.1.0"}`)
	if code != http.StatusOK {
		t.Fatalf("upgrade: %d %s", code, body)
	}
	var upOut struct {
		Deploy orchestrator.DeployResult `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &upOut); err != nil {
		t.Fatal(err)
	}
	if upOut.Deploy.Version != "1.1.0" || upOut.Deploy.Status != "upgrading" {
		t.Errorf("upgrade result = %+v", upOut.Deploy)
	}
	if len(queue.cmds) != 2 {
		t.Errorf("queued commands = %d, want 2 (deploy + upgrade)", len(queue.cmds))
	}
	// The instance manifest carries the user spec; the new 1.1.0 field shows
	// up in the version's schema served by the catalog.
	inst := git.Files("inari-dev/acme-inari-state", "main")["clusters/cluster-1/postgres-aws/db1/instance.yaml"]
	if !strings.Contains(inst, "storageGB: 20") {
		t.Errorf("upgraded manifest lost user spec:\n%s", inst)
	}
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/catalog/curated:postgres-aws", "good", "")
	if code != http.StatusOK || !strings.Contains(body, "multiAZ") {
		t.Errorf("1.1.0 schema with multiAZ not served: %d", code)
	}
	var v string
	if err := database.Pool.QueryRow(context.Background(),
		`SELECT version FROM resource_instances WHERE id = 'db1'`).Scan(&v); err != nil || v != "1.1.0" {
		t.Errorf("instance version = %q err=%v", v, err)
	}
}

// TestGitConfigBYOApp covers the hybrid git app model API surface: BYO
// credential reference round-trip, 422 validation, writer COALESCE
// protection, and provider status surfacing.
func TestGitConfigBYOApp(t *testing.T) {
	srv, database, _, _ := itServer(t)
	defer srv.Close()
	ctx := context.Background()

	// 422: partial BYO object (missing keyRef).
	code, body := itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","commitPolicy":"direct","githubApp":{"appId":7,"installationId":8}}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("partial githubApp: %d %s", code, body)
	}

	// 422: http (non-TLS) apiBase.
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","githubApp":{"appId":7,"installationId":8,"apiBase":"http://ghe.example.com/api/v3","keyRef":{"namespace":"tenant-acme","secretName":"gh","key":"k.pem"}}}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("http apiBase: %d %s", code, body)
	}

	// Valid BYO config round-trips.
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","commitPolicy":"pull_request","baseBranch":"main","githubApp":{"appId":7,"installationId":8,"apiBase":"https://ghe.example.com/api/v3","keyRef":{"namespace":"tenant-acme","secretName":"gh","key":"k.pem"}}}`)
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("set BYO git config: %d %s", code, body)
	}
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/git-config", "good", "")
	if code != http.StatusOK {
		t.Fatalf("get git config: %d %s", code, body)
	}
	var out struct {
		Config types.TenantGitConfig    `json:"config"`
		Status *types.GitProviderStatus `json:"gitProviderStatus,omitempty"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	app := out.Config.GitHubApp
	if app == nil || app.AppID != 7 || app.InstallationID != 8 || app.APIBase != "https://ghe.example.com/api/v3" {
		t.Fatalf("BYO app did not round-trip: %+v", app)
	}
	if app.KeyRef == nil || app.KeyRef.Namespace != "tenant-acme" || app.KeyRef.SecretName != "gh" || app.KeyRef.Key != "k.pem" {
		t.Fatalf("keyRef did not round-trip: %+v", app.KeyRef)
	}
	// StaticResolver (fake) reports an unknown/static status, never an error.
	if out.Status == nil || out.Status.State != "unknown" {
		t.Fatalf("status = %+v, want unknown", out.Status)
	}

	// A writer that doesn't know the override (TZF-style upsert without
	// githubApp) must not wipe it.
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO tenant_git_configs (org_id, repo, commit_policy, base_branch) VALUES ('org:1','acme/acme-inari-state','direct','main')
		 ON CONFLICT (org_id) DO UPDATE SET repo = EXCLUDED.repo`); err != nil {
		t.Fatal(err)
	}
	inv := inventory.NewStore()
	cfg, err := inv.GitConfig(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHubApp == nil || cfg.GitHubApp.AppID != 7 {
		t.Fatalf("BYO app wiped by plain upsert: %+v", cfg.GitHubApp)
	}

	// 422: clearGithubApp combined with githubApp.
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","clearGithubApp":true,"githubApp":{"appId":7,"installationId":8,"keyRef":{"namespace":"tenant-acme","secretName":"gh","key":"k.pem"}}}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("clear+set combo: %d %s", code, body)
	}

	// Explicit clear removes the BYO override (revert to model A).
	code, body = itReq(t, srv, "PUT", "/api/v1/tenants/acme/git-config", "good",
		`{"repo":"acme/acme-inari-state","commitPolicy":"direct","baseBranch":"main","clearGithubApp":true}`)
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("clear BYO git config: %d %s", code, body)
	}
	cfg, err = inv.GitConfig(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHubApp != nil {
		t.Fatalf("BYO app not cleared: %+v", cfg.GitHubApp)
	}
}

// TestGitConfigAllOrNoneConstraint verifies the migration CHECK rejects
// partial credential columns at the DB level.
func TestGitConfigAllOrNoneConstraint(t *testing.T) {
	srv, database, _, _ := itServer(t)
	defer srv.Close()
	ctx := context.Background()
	_, err := database.Pool.Exec(ctx,
		`UPDATE tenant_git_configs SET github_app_id = 1 WHERE org_id = 'org:1'`)
	if err == nil {
		t.Fatal("partial BYO columns accepted; want CHECK violation")
	}
}
