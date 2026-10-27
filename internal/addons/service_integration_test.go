//go:build integration

// Integration tests for the addons service over a real migrated Postgres
// with the fake git provider (adopt/update/enable-prune/discovery flows).
package addons

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

func setupAddonTest(t *testing.T) (*db.DB, context.Context) {
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
	return database, ctx
}

func seedOrg(t *testing.T, database *db.DB, ctx context.Context, id, slug string) {
	t.Helper()
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ($1,$2,$3,$4)`,
		id, slug, slug+" display", "kc-"+slug); err != nil {
		t.Fatal(err)
	}
}

func seedClusterRow(t *testing.T, database *db.DB, ctx context.Context, id, orgID, name string, labels map[string]string) {
	t.Helper()
	raw, _ := json.Marshal(labels)
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO clusters (id, org_id, name, labels, state) VALUES ($1,$2,$3,$4,'active')`, id, orgID, name, raw); err != nil {
		t.Fatal(err)
	}
}

// dbClusterLister is a minimal DB-backed ClusterLister for tests.
type dbClusterLister struct {
	database *db.DB
}

func (l dbClusterLister) GetCluster(ctx context.Context, id string) (*types.Cluster, error) {
	var c types.Cluster
	var labels []byte
	err := l.database.Pool.QueryRow(ctx,
		`SELECT id, org_id, name, state, COALESCE(labels::text,'{}') FROM clusters WHERE id = $1`, id).
		Scan(&c.ID, &c.OrgID, &c.Name, &c.State, &labels)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(labels, &c.Labels)
	return &c, nil
}

func (l dbClusterLister) ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error) {
	rows, err := l.database.Pool.Query(ctx,
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

// repoStoreAdapter adapts inventory.Store to gitprovider.RepoStore.
type repoStoreAdapter struct {
	s  *inventory.Store
	db *db.DB
}

func (a repoStoreAdapter) GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	return a.s.GetGitRepo(ctx, a.db.Pool, orgID, id)
}

func (a repoStoreAdapter) GetDefaultGitRepo(ctx context.Context, orgID string) (*types.TenantGitRepo, error) {
	return a.s.GetDefaultGitRepo(ctx, a.db.Pool, orgID)
}

type capturedQueue struct{ cmds []types.AgentCommand }

func (q *capturedQueue) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	q.cmds = append(q.cmds, *cmd)
	return nil
}

// env bundles one wired addons service test environment.
type env struct {
	db       *db.DB
	store    *inventory.Store
	catalog  *catalog.Service
	git      *gitprovider.Fake
	queue    *capturedQueue
	svc      *Service
	baseline *types.TenantGitRepo
}

func newEnv(t *testing.T, database *db.DB, policy types.CommitPolicy) *env {
	t.Helper()
	ctx := context.Background()
	seedOrg(t, database, ctx, "org:1", "acme")
	invStore := inventory.NewStore()
	auditStore := audit.NewStore()
	catSvc := catalog.NewService(database, catalog.NewStore(), nil, auditStore, nil)
	if err := catSvc.SeedPlatformApps(ctx); err != nil {
		t.Fatal(err)
	}
	git := gitprovider.NewFake()
	repoResolver := gitprovider.NewRepoResolver(repoStoreAdapter{invStore, database}, nil, gitprovider.StaticResolver{P: git})
	queue := &capturedQueue{}
	svc := NewService(database, invStore, catSvc, dbClusterLister{database}, repoResolver, queue, auditStore)

	baseline := &types.TenantGitRepo{
		OrgID: "org:1", Name: "baseline", Repo: "acme/acme-inari-state",
		Scope: types.GitRepoScopePlatform, CommitPolicy: policy, BaseBranch: "main", IsDefault: true,
	}
	if err := invStore.UpsertGitRepo(ctx, database.Pool, baseline); err != nil {
		t.Fatal(err)
	}
	if _, err := git.EnsureRepo(ctx, baseline.Repo); err != nil {
		t.Fatal(err)
	}
	return &env{db: database, store: invStore, catalog: catSvc, git: git, queue: queue, svc: svc, baseline: baseline}
}

func TestAdoptUpdateEnablePruneEndToEnd(t *testing.T) {
	database, ctx := setupAddonTest(t)
	e := newEnv(t, database, types.CommitPolicyDirect)
	seedClusterRow(t, database, ctx, "c1", "org:1", "prod-eu", map[string]string{"env": "prod"})

	// Discovery first: the scanner reports a helm release.
	if err := e.svc.IngestDiscovery(ctx, "org:1", "c1", []DiscoveredAddon{{
		CatalogItem: "platform:cert-manager", ReleaseName: "cert-manager",
		Namespace: "cert-manager", DetectedVersion: "v1.15.0",
		Chart: "cert-manager", RepoURL: "https://charts.jetstack.io",
	}}); err != nil {
		t.Fatal(err)
	}
	disc, err := e.store.GetClusterAddon(ctx, database.Pool, "org:1", "c1", "platform:cert-manager")
	if err != nil {
		t.Fatal(err)
	}
	if disc.State != types.AddonStateDiscovered || disc.ChartVersion != "v1.15.0" || disc.DiscoveredMeta == nil {
		t.Fatalf("discovered row: %+v", disc)
	}

	// Adopt with schema-valid values.
	res, err := e.svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", Values: json.RawMessage(`{"crds":{"enabled":true}}`),
	}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Addon.ID != disc.ID {
		t.Errorf("adopt preserved discovered ID %q → %q", disc.ID, res.Addon.ID)
	}
	persisted, err := e.store.GetClusterAddonByID(ctx, database.Pool, "org:1", res.Addon.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != types.AddonStateManaged || persisted.RepoID != e.baseline.ID ||
		persisted.CommitSHA == "" || persisted.PRURL != "" || persisted.PruneEnabled ||
		persisted.Namespace != "cert-manager" || persisted.ArgoCDApp != "inari-addon-"+persisted.ID {
		t.Errorf("persisted row: %+v", persisted)
	}
	files := e.git.Files("acme/acme-inari-state", "main")
	if !strings.Contains(files["addons/cert-manager/application.yaml"], "prune: false") {
		t.Error("adoption renders prune OFF")
	}
	if len(e.queue.cmds) != 1 {
		t.Fatalf("registration command count = %d", len(e.queue.cmds))
	}

	// Discovery re-report over the managed row: real SQL WHERE guard.
	if err := e.svc.IngestDiscovery(ctx, "org:1", "c1", []DiscoveredAddon{{
		CatalogItem: "platform:cert-manager", DetectedVersion: "v1.15.0", Chart: "cert-manager",
	}}); err != nil {
		t.Fatal(err)
	}
	after, _ := e.store.GetClusterAddonByID(ctx, database.Pool, "org:1", res.Addon.ID)
	if after.State != types.AddonStateManaged || after.ChartVersion != "v1.16.1" {
		t.Errorf("discovery overwrote managed row: %+v", after)
	}

	// Schema-invalid update is rejected without a git write.
	badVersion := "v1.16.2"
	badValues := json.RawMessage(`{"replicaCount":0}`)
	if _, err := e.svc.Update(ctx, "org:1", res.Addon.ID, UpdateInput{ChartVersion: &badVersion, Values: &badValues}, "user:u1"); err == nil {
		t.Fatal("invalid values must be rejected")
	}
	if strings.Contains(e.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/values.yaml"], "replicaCount") {
		t.Error("rejected update must not commit")
	}

	// Valid version bump commits + re-registers.
	goodValues := json.RawMessage(`{"replicaCount":2}`)
	upd, err := e.svc.Update(ctx, "org:1", res.Addon.ID, UpdateInput{ChartVersion: &badVersion, Values: &goodValues}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if upd.Addon.ChartVersion != "v1.16.2" {
		t.Errorf("chart version = %q", upd.Addon.ChartVersion)
	}
	app := e.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/application.yaml"]
	if !strings.Contains(app, "targetRevision: v1.16.2") {
		t.Error("application must pin the new chart version")
	}

	// Enable prune: re-render with prune, audit-flip, conflict on repeat.
	pr, err := e.svc.EnablePrune(ctx, "org:1", res.Addon.ID, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if !pr.Addon.PruneEnabled {
		t.Error("prune flag must persist")
	}
	if !strings.Contains(e.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/application.yaml"], "prune: true") {
		t.Error("enable-prune re-renders prune: true")
	}
	if _, err := e.svc.EnablePrune(ctx, "org:1", res.Addon.ID, "user:u1"); !errors.Is(err, ErrPruneAlreadyEnabled) {
		t.Errorf("repeat: want ErrPruneAlreadyEnabled, got %v", err)
	}
	persisted, _ = e.store.GetClusterAddonByID(ctx, database.Pool, "org:1", res.Addon.ID)
	if !persisted.PruneEnabled {
		t.Error("prune_enabled must be stored")
	}

	// Audit trail exists for adopt + update + enable-prune.
	var auditCount int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE object_type = 'cluster_addon' AND object_id = $1`, res.Addon.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount < 3 {
		t.Errorf("audit events = %d, want >= 3", auditCount)
	}
}

func TestAdoptPullRequestIntegration(t *testing.T) {
	database, ctx := setupAddonTest(t)
	e := newEnv(t, database, types.CommitPolicyPullRequest)
	seedClusterRow(t, database, ctx, "c1", "org:1", "prod", nil)

	res, err := e.svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{Version: "v1.16.1"}, "user:u1")
	if err != nil {
		t.Fatal(err)
	}
	if res.PRURL == "" || len(e.git.PRs) != 1 {
		t.Fatalf("PR policy: pr=%q prs=%+v", res.PRURL, e.git.PRs)
	}
	if len(e.queue.cmds) != 0 {
		t.Error("no registration until the PR merges (documented gap)")
	}
	persisted, err := e.store.GetClusterAddonByID(ctx, database.Pool, "org:1", res.Addon.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.PRURL != res.PRURL {
		t.Errorf("stored prUrl %q ≠ result %q", persisted.PRURL, res.PRURL)
	}
}

func TestFleetReconcileIntegration(t *testing.T) {
	database, ctx := setupAddonTest(t)
	e := newEnv(t, database, types.CommitPolicyDirect)
	seedClusterRow(t, database, ctx, "c1", "org:1", "prod-eu", map[string]string{"env": "prod"})

	// A scanner-reported discovered row exists on the cluster pre-adopt.
	if err := e.svc.IngestDiscovery(ctx, "org:1", "c1", []DiscoveredAddon{{
		CatalogItem: "platform:cert-manager", ReleaseName: "cert-manager",
		Namespace: "cert-manager", DetectedVersion: "v1.16.0",
	}}); err != nil {
		t.Fatal(err)
	}

	if _, err := e.svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", DeployMode: types.AddonDeployModeApplicationSet,
		ClusterSelector: map[string]string{"env": "prod"},
	}, "user:u1"); err != nil {
		t.Fatal(err)
	}
	if len(e.queue.cmds) != 1 || e.queue.cmds[0].Type != RegisterAppSetEventType {
		t.Fatalf("appset command: %+v", e.queue.cmds)
	}

	// The per-cluster discovered row was absorbed by the fleet row (SQL).
	if _, err := e.store.GetClusterAddon(ctx, database.Pool, "org:1", "c1", "platform:cert-manager"); !errors.Is(err, inventory.ErrAddonNotFound) {
		t.Errorf("discovered row should be absorbed, got %v", err)
	}
	fleetRow, err := e.store.GetClusterAddon(ctx, database.Pool, "org:1", "*", "platform:cert-manager")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fleetRow.DiscoveredMeta), "absorbedSightings") {
		t.Errorf("fleet discovered_meta = %s, want absorbed sightings", fleetRow.DiscoveredMeta)
	}

	// Register a second matching cluster; the outbox consumer re-renders.
	seedClusterRow(t, database, ctx, "c2", "org:1", "prod-us", map[string]string{"env": "prod"})
	reconciler := NewFleetReconciler(e.svc, nil)
	if err := reconciler.Handle(ctx, &types.OutboxEvent{
		Payload: json.RawMessage(`{"orgId":"org:1","clusterId":"c2","name":"prod-us"}`),
	}); err != nil {
		t.Fatal(err)
	}
	appset := e.git.Files("acme/acme-inari-state", "main")["addons/cert-manager/applicationset.yaml"]
	if !strings.Contains(appset, "cluster: prod-us") || !strings.Contains(appset, "cluster: prod-eu") {
		t.Errorf("fleet membership did not expand:\n%s", appset)
	}

	// Baseline selector: the adopt defaulted to the cluster's baseline.
	sel, err := e.store.BaselineRepoSelector(ctx, database.Pool, "org:1", "c1")
	if err != nil || sel == "" {
		t.Errorf("baseline selector = %q, %v", sel, err)
	}
}

// PR-policy fleet reconcile: the adopt opens a PR instead of committing,
// so the base branch keeps showing drift and each membership change opens
// a follow-up PR carrying the expanded fleet. This pins the current
// behavior as the regression baseline for the planned PR-merge webhook
// finalizer (documented duplicate-PR gap).
func TestFleetReconcilePullRequestPolicy(t *testing.T) {
	database, ctx := setupAddonTest(t)
	e := newEnv(t, database, types.CommitPolicyPullRequest)
	seedClusterRow(t, database, ctx, "c1", "org:1", "prod-eu", map[string]string{"env": "prod"})

	if _, err := e.svc.Adopt(ctx, "org:1", "c1", "platform:cert-manager", AdoptInput{
		Version: "v1.16.1", DeployMode: types.AddonDeployModeApplicationSet,
		ClusterSelector: map[string]string{"env": "prod"},
	}, "user:u1"); err != nil {
		t.Fatal(err)
	}
	if len(e.git.PRs) != 1 {
		t.Fatalf("adopt PRs = %d, want 1", len(e.git.PRs))
	}
	if len(e.queue.cmds) != 0 {
		t.Errorf("PR policy must not register pre-merge: %+v", e.queue.cmds)
	}

	seedClusterRow(t, database, ctx, "c2", "org:1", "prod-us", map[string]string{"env": "prod"})
	reconciler := NewFleetReconciler(e.svc, nil)
	if err := reconciler.Handle(ctx, &types.OutboxEvent{
		Payload: json.RawMessage(`{"orgId":"org:1","clusterId":"c2","name":"prod-us"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if len(e.git.PRs) != 2 {
		t.Fatalf("reconcile PRs = %d, want 2 (documented duplicate-PR gap)", len(e.git.PRs))
	}
	var expanded bool
	for _, f := range e.git.PRs[1].Files {
		if f.Path == "addons/cert-manager/applicationset.yaml" &&
			strings.Contains(string(f.Content), "cluster: prod-us") &&
			strings.Contains(string(f.Content), "cluster: prod-eu") {
			expanded = true
		}
	}
	if !expanded {
		t.Errorf("reconcile PR must carry the expanded fleet: %+v", e.git.PRs[1].Files)
	}

	// Redelivery under PR policy is NOT idempotent: drift is measured
	// against the base branch, which only gains the files at merge time —
	// every event opens another PR until then. This is the documented
	// duplicate-PR gap the webhook finalizer will close; the assertion
	// pins the baseline so the fix flips it deliberately.
	if err := reconciler.Handle(ctx, &types.OutboxEvent{
		Payload: json.RawMessage(`{"orgId":"org:1","clusterId":"c2","name":"prod-us"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if len(e.git.PRs) != 3 {
		t.Errorf("pre-finalizer baseline: redelivery opens another PR, got %d PRs", len(e.git.PRs))
	}
}
