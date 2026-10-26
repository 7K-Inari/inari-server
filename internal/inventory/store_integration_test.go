//go:build integration

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

func setupStoreTest(t *testing.T) (*db.DB, context.Context) {
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

func seedTeam(t *testing.T, database *db.DB, ctx context.Context, orgID, name string) string {
	t.Helper()
	var roleID string
	if err := database.Pool.QueryRow(ctx,
		`INSERT INTO roles (org_id, name, display_name, builtin, permissions) VALUES ($1,$2,$3,false,'[]') RETURNING id`,
		orgID, "role-"+name, "role-"+name).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := database.Pool.QueryRow(ctx,
		`INSERT INTO teams (org_id, name, role_id, keycloak_group_path) VALUES ($1,$2,$3,$4) RETURNING id`,
		orgID, name, roleID, "/"+orgID+"/"+name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedCluster(t *testing.T, database *db.DB, ctx context.Context, orgID, name string) string {
	t.Helper()
	id := newULID()
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, id, orgID, name); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGitRepoCRUD(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	teamA := seedTeam(t, database, ctx, "org:1", "team-a")
	teamB := seedTeam(t, database, ctx, "org:1", "team-b")
	s := NewStore()

	baseline := &types.TenantGitRepo{
		OrgID: "org:1", Name: "baseline", Repo: "acme/acme-inari-state",
		Scope: types.GitRepoScopePlatform, IsDefault: true,
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, baseline); err != nil {
		t.Fatalf("upsert baseline: %v", err)
	}
	if baseline.ID == "" {
		t.Fatal("expected generated ULID")
	}

	teamRepo := &types.TenantGitRepo{
		OrgID: "org:1", Name: "team-a-gitops", Repo: "acme/team-a-gitops",
		Scope: types.GitRepoScopeTeam, TeamID: teamA,
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, teamRepo); err != nil {
		t.Fatalf("upsert team repo: %v", err)
	}

	got, err := s.GetGitRepo(ctx, database.Pool, "org:1", baseline.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Repo != "acme/acme-inari-state" || !got.IsDefault || got.Scope != types.GitRepoScopePlatform {
		t.Errorf("unexpected repo: %+v", got)
	}
	if got.Provider != types.GitRepoProviderGitHub || got.CommitPolicy != types.CommitPolicyDirect || got.BaseBranch != "main" {
		t.Errorf("defaults not applied: %+v", got)
	}
	if _, err := s.GetGitRepo(ctx, database.Pool, "org:1", "missing"); !errors.Is(err, ErrRepoNotFound) {
		t.Errorf("want ErrRepoNotFound, got %v", err)
	}

	def, err := s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if err != nil || def.ID != baseline.ID {
		t.Errorf("default = %+v, %v", def, err)
	}

	// List: platform view (nil team) sees everything.
	all, err := s.ListGitRepos(ctx, database.Pool, "org:1", nil)
	if err != nil || len(all) != 2 {
		t.Fatalf("list all = %d, %v", len(all), err)
	}
	// Team A sees baseline + its own repo.
	aView, err := s.ListGitRepos(ctx, database.Pool, "org:1", []string{teamA})
	if err != nil || len(aView) != 2 {
		t.Fatalf("team A list = %d, %v", len(aView), err)
	}
	// Team B sees only the baseline.
	bView, err := s.ListGitRepos(ctx, database.Pool, "org:1", []string{teamB})
	if err != nil || len(bView) != 1 || bView[0].Name != "baseline" {
		t.Fatalf("team B list = %+v, %v", bView, err)
	}
	// A user in both teams sees baseline + both team repos.
	abView, err := s.ListGitRepos(ctx, database.Pool, "org:1", []string{teamA, teamB})
	if err != nil || len(abView) != 2 {
		t.Fatalf("multi-team list = %d, %v", len(abView), err)
	}

	// Upsert same name updates in place.
	teamRepo2 := &types.TenantGitRepo{
		OrgID: "org:1", Name: "team-a-gitops", Repo: "acme/team-a-gitops-v2",
		Scope: types.GitRepoScopeTeam, TeamID: teamA, CommitPolicy: types.CommitPolicyPullRequest,
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, teamRepo2); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, err = s.GetGitRepo(ctx, database.Pool, "org:1", teamRepo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Repo != "acme/team-a-gitops-v2" || got.CommitPolicy != types.CommitPolicyPullRequest {
		t.Errorf("update not applied: %+v", got)
	}

	// Delete: default is blocked; team repo deletes.
	if err := s.DeleteGitRepo(ctx, database.Pool, "org:1", baseline.ID); !errors.Is(err, ErrRepoInUse) {
		t.Errorf("delete default: want ErrRepoInUse, got %v", err)
	}
	if err := s.DeleteGitRepo(ctx, database.Pool, "org:1", teamRepo.ID); err != nil {
		t.Errorf("delete team repo: %v", err)
	}
	if err := s.DeleteGitRepo(ctx, database.Pool, "org:1", teamRepo.ID); !errors.Is(err, ErrRepoNotFound) {
		t.Errorf("re-delete: want ErrRepoNotFound, got %v", err)
	}
}

func TestSetDefaultGitRepo(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	r1 := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state-1",
		Scope: types.GitRepoScopePlatform, IsDefault: true}
	r2 := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline-2", Repo: "acme/state-2",
		Scope: types.GitRepoScopePlatform}
	if err := s.UpsertGitRepo(ctx, database.Pool, r1); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, r2); err != nil {
		t.Fatal(err)
	}

	if err := database.WithTx(ctx, func(tx pgx.Tx) error {
		return s.SetDefaultGitRepo(ctx, tx, "org:1", r2.ID)
	}); err != nil {
		t.Fatalf("set default: %v", err)
	}
	def, err := s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if err != nil || def.ID != r2.ID {
		t.Errorf("default = %+v, %v", def, err)
	}
	old, err := s.GetGitRepo(ctx, database.Pool, "org:1", r1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if old.IsDefault {
		t.Error("previous default still flagged")
	}
}

// TestSetDefaultGitRepoRejectsTeamScope pins the store-level scope guard:
// the default slot is platform-only (the orchestrator's team-write
// enforcement skips empty selectors, so a team-scope default would be
// writable by any org member). A team-scope target reads as
// ErrRepoNotFound and leaves the current default untouched.
func TestSetDefaultGitRepoRejectsTeamScope(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	teamID := seedTeam(t, database, ctx, "org:1", "team-a")
	s := NewStore()

	baseline := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state",
		Scope: types.GitRepoScopePlatform, IsDefault: true}
	teamRepo := &types.TenantGitRepo{OrgID: "org:1", Name: "team-a", Repo: "acme/team-a",
		Scope: types.GitRepoScopeTeam, TeamID: teamID}
	if err := s.UpsertGitRepo(ctx, database.Pool, baseline); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, teamRepo); err != nil {
		t.Fatal(err)
	}

	err := database.WithTx(ctx, func(tx pgx.Tx) error {
		return s.SetDefaultGitRepo(ctx, tx, "org:1", teamRepo.ID)
	})
	if !errors.Is(err, ErrRepoNotFound) {
		t.Fatalf("team-scope promote: want ErrRepoNotFound, got %v", err)
	}
	def, derr := s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if derr != nil || def.ID != baseline.ID {
		t.Errorf("default changed after rejected promote: %+v, %v", def, derr)
	}
}

func TestGitRepoBYOApp(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	r := &types.TenantGitRepo{
		OrgID: "org:1", Name: "byo", Repo: "acme/byo", Scope: types.GitRepoScopeTeam,
		GitHubApp: &types.GitHubAppConfig{
			AppID: 42, InstallationID: 7, APIBase: "https://ghe.example.com/api/v3",
			KeyRef: &types.GitHubAppSecretRef{Namespace: "eso", SecretName: "key", Key: "private-key.pem"},
		},
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, r); err != nil {
		t.Fatalf("upsert byo: %v", err)
	}
	got, err := s.GetGitRepo(ctx, database.Pool, "org:1", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.GitHubApp == nil || got.GitHubApp.AppID != 42 || got.GitHubApp.KeyRef.SecretName != "key" ||
		got.GitHubApp.APIBase != "https://ghe.example.com/api/v3" {
		t.Errorf("BYO round-trip failed: %+v", got.GitHubApp)
	}

	// Preserve-on-omit: update without GitHubApp keeps the stored reference.
	upd := &types.TenantGitRepo{OrgID: "org:1", Name: "byo", Repo: "acme/byo-2", Scope: types.GitRepoScopeTeam}
	if err := s.UpsertGitRepo(ctx, database.Pool, upd); err != nil {
		t.Fatal(err)
	}
	// The conflict path must hand back the existing row's ID, not the
	// freshly generated one (scaffold registering-repo retry depends on it).
	if upd.ID != r.ID {
		t.Errorf("conflict upsert ID = %q, want existing %q", upd.ID, r.ID)
	}
	got, _ = s.GetGitRepo(ctx, database.Pool, "org:1", r.ID)
	if got.GitHubApp == nil || got.GitHubApp.AppID != 42 {
		t.Errorf("preserve-on-omit failed: %+v", got.GitHubApp)
	}

	// ClearGitHubApp NULLs the columns.
	clr := &types.TenantGitRepo{OrgID: "org:1", Name: "byo", Repo: "acme/byo-2",
		Scope: types.GitRepoScopeTeam, ClearGitHubApp: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, clr); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetGitRepo(ctx, database.Pool, "org:1", r.ID)
	if got.GitHubApp != nil {
		t.Errorf("clear failed: %+v", got.GitHubApp)
	}

	// All-or-nothing CHECK: partial BYO columns are rejected at the SQL level.
	_, err = database.Pool.Exec(ctx, `INSERT INTO tenant_git_repos
		(id, org_id, name, repo, scope, github_app_id) VALUES ('x', 'org:1', 'bad', 'acme/bad', 'team', 1)`)
	if err == nil {
		t.Error("expected CHECK violation for partial BYO columns")
	}
	// api_base requires an app.
	_, err = database.Pool.Exec(ctx, `INSERT INTO tenant_git_repos
		(id, org_id, name, repo, scope, github_app_api_base) VALUES ('y', 'org:1', 'bad2', 'acme/bad2', 'team', 'https://ghe')`)
	if err == nil {
		t.Error("expected CHECK violation for api_base without app")
	}
}

func TestBindClusterBaseline(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	seedOrg(t, database, ctx, "org:2", "other")
	clusterID := seedCluster(t, database, ctx, "org:1", "prod")
	s := NewStore()

	platform := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state",
		Scope: types.GitRepoScopePlatform, IsDefault: true}
	team := &types.TenantGitRepo{OrgID: "org:1", Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam}
	crossOrg := &types.TenantGitRepo{OrgID: "org:2", Name: "baseline", Repo: "other/state",
		Scope: types.GitRepoScopePlatform, IsDefault: true}
	for _, r := range []*types.TenantGitRepo{platform, team, crossOrg} {
		if err := s.UpsertGitRepo(ctx, database.Pool, r); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.BindClusterBaseline(ctx, database.Pool, clusterID, platform.ID); err != nil {
		t.Fatalf("bind platform: %v", err)
	}
	var bound string
	if err := database.Pool.QueryRow(ctx, `SELECT baseline_repo_id FROM clusters WHERE id = $1`, clusterID).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if bound != platform.ID {
		t.Errorf("bound = %q, want %q", bound, platform.ID)
	}

	if err := s.BindClusterBaseline(ctx, database.Pool, clusterID, team.ID); !errors.Is(err, ErrRepoNotFound) {
		t.Errorf("bind team-scope: want ErrRepoNotFound, got %v", err)
	}
	if err := s.BindClusterBaseline(ctx, database.Pool, clusterID, crossOrg.ID); !errors.Is(err, ErrRepoNotFound) {
		t.Errorf("bind cross-org: want ErrRepoNotFound, got %v", err)
	}
}

func TestGitConfigBackCompatProxy(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	// Legacy write creates the default repo row.
	cfg := &types.TenantGitConfig{
		OrgID: "org:1", Repo: "acme/acme-inari-state",
		CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
	}
	if err := s.UpsertGitConfig(ctx, database.Pool, cfg); err != nil {
		t.Fatalf("upsert config: %v", err)
	}
	def, err := s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatalf("default repo not created: %v", err)
	}
	if def.Name != "baseline" || def.Scope != types.GitRepoScopePlatform || def.Repo != "acme/acme-inari-state" {
		t.Errorf("unexpected default: %+v", def)
	}

	// Legacy write updates the default row.
	cfg.Repo = "acme/acme-state-v2"
	if err := s.UpsertGitConfig(ctx, database.Pool, cfg); err != nil {
		t.Fatal(err)
	}
	def, _ = s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if def.Repo != "acme/acme-state-v2" {
		t.Errorf("proxy update failed: %+v", def)
	}

	// Read path: GitConfig.Repo proxies the default repo even if the legacy
	// column diverges.
	if _, err := database.Pool.Exec(ctx, `UPDATE tenant_git_configs SET repo = 'acme/stale' WHERE org_id = 'org:1'`); err != nil {
		t.Fatal(err)
	}
	got, err := s.GitConfig(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Repo != "acme/acme-state-v2" {
		t.Errorf("read proxy = %q, want default repo", got.Repo)
	}

	// Policy/branch proxy too: a PATCH on the git-repos API (which updates
	// only the registry row) must not leave the legacy view stale.
	if _, err := database.Pool.Exec(ctx, `UPDATE tenant_git_repos SET commit_policy = 'pull_request', base_branch = 'trunk'
		WHERE org_id = 'org:1' AND is_default`); err != nil {
		t.Fatal(err)
	}
	got, err = s.GitConfig(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitPolicy != types.CommitPolicyPullRequest || got.BaseBranch != "trunk" {
		t.Errorf("policy/branch proxy = %q/%q, want pull_request/trunk", got.CommitPolicy, got.BaseBranch)
	}
}

func TestMigrationBackfill(t *testing.T) {
	// A database migrated from scratch runs 0033's backfill over any
	// pre-existing tenant_git_configs rows. Seed via the legacy table before
	// the registry exists is impossible on a fresh DB (migrations run to
	// latest), so instead verify the backfill INSERT shape: a legacy write
	// through UpsertGitConfig plus a manual replay of the backfill statement
	// must not conflict (idempotent path is the store's, tested above).
	// Here we assert the schema invariants directly.
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")

	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_indexes WHERE indexname = 'one_default_repo_per_org'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Error("partial unique index one_default_repo_per_org missing")
	}
}

func TestClusterAddonCRUD(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	clusterID := seedCluster(t, database, ctx, "org:1", "prod")
	s := NewStore()

	repo := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state",
		Scope: types.GitRepoScopePlatform, IsDefault: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, repo); err != nil {
		t.Fatal(err)
	}

	addon := &types.ClusterAddon{
		OrgID: "org:1", ClusterID: clusterID, CatalogItem: "platform:cert-manager",
		State: types.AddonStateDiscovered,
		Source: types.SourceDescriptor{
			Kind: types.SourceKindHelm,
			Helm: &types.HelmSource{RepoURL: "https://charts.jetstack.io", Chart: "cert-manager", Version: "v1.14.0"},
		},
		ChartVersion:   "v1.14.0",
		DiscoveredMeta: json.RawMessage(`{"release":"cert-manager","namespace":"cert-manager"}`),
	}
	if err := s.UpsertClusterAddon(ctx, database.Pool, addon); err != nil {
		t.Fatalf("upsert discovered: %v", err)
	}
	if addon.ID == "" {
		t.Fatal("expected generated ULID")
	}

	got, err := s.GetClusterAddon(ctx, database.Pool, "org:1", clusterID, "platform:cert-manager")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != types.AddonStateDiscovered || got.Source.Kind != types.SourceKindHelm ||
		got.Source.Helm.Chart != "cert-manager" || got.ChartVersion != "v1.14.0" {
		t.Errorf("unexpected addon: %+v", got)
	}

	// Adopt: managed with repo binding.
	managed := &types.ClusterAddon{
		OrgID: "org:1", ClusterID: clusterID, CatalogItem: "platform:cert-manager",
		State: types.AddonStateManaged, DeployMode: types.AddonDeployModeApplication,
		RepoID: repo.ID, RepoPath: "addons/cert-manager",
		Source:       addon.Source,
		ChartVersion: "v1.14.0",
		Values:       json.RawMessage(`{"installCRDs":true}`),
		ArgoCDApp:    "inari-addon-abc",
	}
	if err := s.UpsertClusterAddon(ctx, database.Pool, managed); err != nil {
		t.Fatalf("upsert managed: %v", err)
	}
	got, _ = s.GetClusterAddon(ctx, database.Pool, "org:1", clusterID, "platform:cert-manager")
	if got.State != types.AddonStateManaged || got.RepoID != repo.ID || got.ArgoCDApp != "inari-addon-abc" {
		t.Errorf("adopt failed: %+v", got)
	}

	// Discovery re-report must not downgrade managed.
	if err := s.UpsertClusterAddon(ctx, database.Pool, addon); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetClusterAddon(ctx, database.Pool, "org:1", clusterID, "platform:cert-manager")
	if got.State != types.AddonStateManaged {
		t.Errorf("discovery downgraded state to %q", got.State)
	}

	// List filters.
	listed, err := s.ListClusterAddons(ctx, database.Pool, "org:1", clusterID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list cluster = %d, %v", len(listed), err)
	}
	listed, err = s.ListClusterAddons(ctx, database.Pool, "org:1", "")
	if err != nil || len(listed) != 1 {
		t.Fatalf("list org = %d, %v", len(listed), err)
	}
	listed, err = s.ListClusterAddons(ctx, database.Pool, "org:1", "other-cluster")
	if err != nil || len(listed) != 0 {
		t.Fatalf("list other = %d, %v", len(listed), err)
	}

	if _, err := s.GetClusterAddon(ctx, database.Pool, "org:1", clusterID, "platform:missing"); !errors.Is(err, ErrAddonNotFound) {
		t.Errorf("want ErrAddonNotFound, got %v", err)
	}

	if err := s.DeleteClusterAddon(ctx, database.Pool, "org:1", got.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteClusterAddon(ctx, database.Pool, "org:1", got.ID); !errors.Is(err, ErrAddonNotFound) {
		t.Errorf("re-delete: want ErrAddonNotFound, got %v", err)
	}
}

func TestGitRepoRefCounts(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	clusterID := seedCluster(t, database, ctx, "org:1", "prod")
	otherCluster := seedCluster(t, database, ctx, "org:1", "staging")
	s := NewStore()

	repo := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state",
		Scope: types.GitRepoScopePlatform, IsDefault: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, repo); err != nil {
		t.Fatal(err)
	}

	// Zero refs on a fresh repo.
	refs, err := s.GitRepoRefCounts(ctx, database.Pool, "org:1", repo.ID)
	if err != nil {
		t.Fatalf("ref counts: %v", err)
	}
	if refs.Instances != 0 || refs.Addons != 0 || refs.Clusters != 0 {
		t.Fatalf("fresh repo refs = %+v, want zero", refs)
	}

	// Bind a cluster to the baseline.
	if err := s.BindClusterBaseline(ctx, database.Pool, clusterID, repo.ID); err != nil {
		t.Fatal(err)
	}

	// An instance on the bound cluster attributes to the repo.
	inst := &types.ResourceInstance{
		ID: "inst-1", OrgID: "org:1", ClusterID: clusterID, CatalogItemID: "platform:cert-manager",
		Version: "v1", Spec: json.RawMessage(`{}`), State: "running", ManagementMode: "adopt",
	}
	if err := s.Create(ctx, database.Pool, inst); err != nil {
		t.Fatal(err)
	}
	// An instance on an unbound cluster does not attribute to the repo.
	inst2 := &types.ResourceInstance{
		ID: "inst-2", OrgID: "org:1", ClusterID: otherCluster, CatalogItemID: "platform:istio",
		Version: "v1", Spec: json.RawMessage(`{}`), State: "running", ManagementMode: "adopt",
	}
	if err := s.Create(ctx, database.Pool, inst2); err != nil {
		t.Fatal(err)
	}

	// A managed addon referencing the repo.
	addon := &types.ClusterAddon{
		OrgID: "org:1", ClusterID: clusterID, CatalogItem: "platform:cert-manager",
		State: types.AddonStateManaged, RepoID: repo.ID, RepoPath: "addons/cert-manager",
		Source: types.SourceDescriptor{Kind: types.SourceKindHelm},
	}
	if err := s.UpsertClusterAddon(ctx, database.Pool, addon); err != nil {
		t.Fatal(err)
	}

	refs, err = s.GitRepoRefCounts(ctx, database.Pool, "org:1", repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refs.Instances != 1 || refs.Addons != 1 || refs.Clusters != 1 {
		t.Errorf("refs = %+v, want {Instances:1 Addons:1 Clusters:1}", refs)
	}

	// Cross-org isolation: refs never leak across orgs.
	seedOrg(t, database, ctx, "org:2", "other")
	otherRepo := &types.TenantGitRepo{OrgID: "org:2", Name: "baseline", Repo: "other/state",
		Scope: types.GitRepoScopePlatform, IsDefault: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, otherRepo); err != nil {
		t.Fatal(err)
	}
	refs, err = s.GitRepoRefCounts(ctx, database.Pool, "org:2", otherRepo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refs.Instances != 0 || refs.Addons != 0 || refs.Clusters != 0 {
		t.Errorf("cross-org refs = %+v, want zero", refs)
	}
}

// TestInstanceRepoIDAttribution pins the Feature A rule: an instance with
// an explicit repo_id attributes to THAT repo (team repo), not to its
// cluster's bound baseline.
func TestInstanceRepoIDAttribution(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	clusterID := seedCluster(t, database, ctx, "org:1", "prod")
	s := NewStore()

	baseline := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state",
		Scope: types.GitRepoScopePlatform, IsDefault: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, baseline); err != nil {
		t.Fatal(err)
	}
	teamRepo := &types.TenantGitRepo{OrgID: "org:1", Name: "team-a", Repo: "acme/team-a",
		Scope: types.GitRepoScopeTeam}
	if err := s.UpsertGitRepo(ctx, database.Pool, teamRepo); err != nil {
		t.Fatal(err)
	}
	if err := s.BindClusterBaseline(ctx, database.Pool, clusterID, baseline.ID); err != nil {
		t.Fatal(err)
	}

	// Instance recorded against the team repo on the baseline-bound cluster.
	inst := &types.ResourceInstance{
		ID: "inst-team", OrgID: "org:1", ClusterID: clusterID, CatalogItemID: "curated:web-service",
		Version: "v1", Spec: json.RawMessage(`{}`), State: "running", ManagementMode: "adopt",
		RepoID: teamRepo.ID,
	}
	if err := s.Create(ctx, database.Pool, inst); err != nil {
		t.Fatal(err)
	}

	// Round-trip: the recorded repo survives a read.
	got, err := s.Get(ctx, database.Pool, "inst-team")
	if err != nil {
		t.Fatal(err)
	}
	if got.RepoID != teamRepo.ID {
		t.Errorf("read repo_id = %q, want %q", got.RepoID, teamRepo.ID)
	}

	// Attributes to the team repo, not the baseline.
	refs, err := s.GitRepoRefCounts(ctx, database.Pool, "org:1", teamRepo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refs.Instances != 1 {
		t.Errorf("team repo instance refs = %d, want 1", refs.Instances)
	}
	refs, err = s.GitRepoRefCounts(ctx, database.Pool, "org:1", baseline.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refs.Instances != 0 {
		t.Errorf("baseline instance refs = %d, want 0 (instance lives on the team repo)", refs.Instances)
	}

	// ListGitRepoInstances follows the same attribution.
	teamInsts, err := s.ListGitRepoInstances(ctx, database.Pool, "org:1", teamRepo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(teamInsts) != 1 || teamInsts[0].ID != "inst-team" {
		t.Errorf("team repo instances = %+v, want [inst-team]", teamInsts)
	}
	baseInsts, err := s.ListGitRepoInstances(ctx, database.Pool, "org:1", baseline.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseInsts) != 0 {
		t.Errorf("baseline instances = %+v, want none", baseInsts)
	}
}
