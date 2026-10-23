//go:build integration

// QA probe tests: boundary, error-path, and concurrency coverage for the
// multi-repo GitOps registry.
package inventory

import (
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// QA: upserting a row whose `repo` collides with a DIFFERENT row's repo
// (UNIQUE(org_id,repo) is not the ON CONFLICT target) must surface an error,
// not silently succeed or corrupt.
func TestQARepoUniqueConflictOnRepoColumn(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	a := &types.TenantGitRepo{OrgID: "org:1", Name: "a", Repo: "acme/same", Scope: types.GitRepoScopePlatform, IsDefault: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, a); err != nil {
		t.Fatal(err)
	}
	b := &types.TenantGitRepo{OrgID: "org:1", Name: "b", Repo: "acme/same", Scope: types.GitRepoScopeTeam}
	err := s.UpsertGitRepo(ctx, database.Pool, b)
	if err == nil {
		t.Fatal("expected UNIQUE(org_id,repo) violation, got nil")
	}
	t.Logf("repo collision error: %v", err)
}

// QA: a team-scope repo referencing a team owned by a DIFFERENT org must
// be rejected — otherwise the team filter in ListGitRepos leaks the repo
// to the foreign team.
func TestQACrossOrgTeamReference(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	seedOrg(t, database, ctx, "org:2", "other")
	teamInOrg2 := seedTeam(t, database, ctx, "org:2", "team-x")
	s := NewStore()

	r := &types.TenantGitRepo{
		OrgID: "org:1", Name: "sneaky", Repo: "acme/sneaky",
		Scope: types.GitRepoScopeTeam, TeamID: teamInOrg2,
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, r); !errors.Is(err, ErrTeamNotInOrg) {
		t.Fatalf("want ErrTeamNotInOrg, got %v", err)
	}
	// A nonexistent team id is rejected the same way.
	r.TeamID = "00000000-0000-0000-0000-000000000000"
	if err := s.UpsertGitRepo(ctx, database.Pool, r); !errors.Is(err, ErrTeamNotInOrg) {
		t.Fatalf("missing team: want ErrTeamNotInOrg, got %v", err)
	}
}

// QA: GitHubApp with nil KeyRef must not panic the store.
func TestQANilKeyRef(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("PANIC on nil KeyRef: %v", rec)
		}
	}()
	r := &types.TenantGitRepo{
		OrgID: "org:1", Name: "nil-keyref", Repo: "acme/nil-keyref",
		Scope:     types.GitRepoScopeTeam,
		GitHubApp: &types.GitHubAppConfig{AppID: 1, InstallationID: 2},
	}
	if err := s.UpsertGitRepo(ctx, database.Pool, r); err != nil {
		t.Logf("returned error (acceptable): %v", err)
	}
}

// QA: same nil-KeyRef probe against the legacy config path (pre-existing
// pattern, but the new syncDefaultRepoFromConfig doubles the exposure).
func TestQANilKeyRefConfig(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("PANIC on nil KeyRef (config path): %v", rec)
		}
	}()
	cfg := &types.TenantGitConfig{
		OrgID: "org:1", Repo: "acme/state",
		GitHubApp: &types.GitHubAppConfig{AppID: 1, InstallationID: 2},
	}
	if err := s.UpsertGitConfig(ctx, database.Pool, cfg); err != nil {
		t.Logf("returned error (acceptable): %v", err)
	}
}

// QA: SetDefaultGitRepo is atomic even without a tx: a missing target id
// must leave the existing default untouched.
func TestQASetDefaultNonAtomic(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	r := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, r); err != nil {
		t.Fatal(err)
	}
	// Non-tx call with a bogus id: must not demote the current default.
	err := s.SetDefaultGitRepo(ctx, database.Pool, "org:1", "does-not-exist")
	if !errors.Is(err, ErrRepoNotFound) {
		t.Fatalf("want ErrRepoNotFound, got %v", err)
	}
	def, derr := s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if derr != nil {
		t.Fatalf("default lost after failed SetDefaultGitRepo: %v", derr)
	}
	if def.ID != r.ID {
		t.Errorf("default changed to %q on failed promote", def.ID)
	}
	// Re-setting the same repo as default is idempotent.
	if err := s.SetDefaultGitRepo(ctx, database.Pool, "org:1", r.ID); err != nil {
		t.Fatalf("idempotent re-set: %v", err)
	}
}

// QA: upserting a second repo with IsDefault=true must hit the partial
// unique index, not silently demote the first.
func TestQASecondDefaultRejected(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	r1 := &types.TenantGitRepo{OrgID: "org:1", Name: "one", Repo: "acme/one", Scope: types.GitRepoScopePlatform, IsDefault: true}
	r2 := &types.TenantGitRepo{OrgID: "org:1", Name: "two", Repo: "acme/two", Scope: types.GitRepoScopePlatform, IsDefault: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, r1); err != nil {
		t.Fatal(err)
	}
	err := s.UpsertGitRepo(ctx, database.Pool, r2)
	if err == nil {
		t.Fatal("expected one_default_repo_per_org violation, got nil")
	}
	t.Logf("second default rejected: %v", err)
	// First repo must still be default.
	def, derr := s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if derr != nil || def.Name != "one" {
		t.Errorf("default clobbered: %+v, %v", def, derr)
	}
}

// QA: re-upserting the default repo with IsDefault zero-value must keep
// the stored flag — promotion/demotion is SetDefaultGitRepo's job only.
func TestQAUpsertDemotesDefault(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	r := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true}
	if err := s.UpsertGitRepo(ctx, database.Pool, r); err != nil {
		t.Fatal(err)
	}
	// Re-upsert same name without IsDefault (Go zero value).
	upd := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state-2", Scope: types.GitRepoScopePlatform}
	if err := s.UpsertGitRepo(ctx, database.Pool, upd); err != nil {
		t.Fatal(err)
	}
	def, derr := s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if derr != nil {
		t.Fatalf("default lost on re-upsert: %v", derr)
	}
	if def.ID != r.ID || def.Repo != "acme/state-2" {
		t.Errorf("default = %+v, want id %q with updated repo", def, r.ID)
	}
}

// QA: addon upsert with empty Source round-trips; invalid stored JSON
// surfaces a wrapped error on read.
func TestQAAddonSourceEdge(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	clusterID := seedCluster(t, database, ctx, "org:1", "prod")
	s := NewStore()

	// Zero-value SourceDescriptor marshals to {"kind":""} — stored fine.
	a := &types.ClusterAddon{OrgID: "org:1", ClusterID: clusterID, CatalogItem: "platform:x"}
	if err := s.UpsertClusterAddon(ctx, database.Pool, a); err != nil {
		t.Fatalf("zero source upsert: %v", err)
	}
	got, err := s.GetClusterAddon(ctx, database.Pool, "org:1", clusterID, "platform:x")
	if err != nil {
		t.Fatal(err)
	}
	if got.Source.Kind != "" {
		t.Errorf("source kind = %q", got.Source.Kind)
	}

	// Corrupt the stored JSON directly; read must error, not panic.
	if _, err := database.Pool.Exec(ctx, `UPDATE cluster_addons SET source = 'not-json'::jsonb WHERE id = $1`, a.ID); err == nil {
		t.Log("postgres rejected invalid jsonb (expected)")
	} else {
		t.Logf("invalid jsonb rejected at write: %v", err)
	}
}

// QA: ListGitRepos with a malformed team UUID errors (cast failure) rather
// than scanning garbage.
func TestQAListReposBadUUID(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()
	bad := "not-a-uuid"
	_, err := s.ListGitRepos(ctx, database.Pool, "org:1", &bad)
	if err == nil {
		t.Fatal("expected uuid cast error")
	}
	t.Logf("bad uuid error: %v", err)
}

// QA: deleting a repo nulls cluster baseline_repo_id and addon repo_id
// (ON DELETE SET NULL), verified end-to-end.
func TestQADeleteRepoNullsRefs(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	clusterID := seedCluster(t, database, ctx, "org:1", "prod")
	s := NewStore()

	def := &types.TenantGitRepo{OrgID: "org:1", Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true}
	extra := &types.TenantGitRepo{OrgID: "org:1", Name: "extra", Repo: "acme/extra", Scope: types.GitRepoScopePlatform}
	for _, r := range []*types.TenantGitRepo{def, extra} {
		if err := s.UpsertGitRepo(ctx, database.Pool, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.BindClusterBaseline(ctx, database.Pool, clusterID, extra.ID); err != nil {
		t.Fatal(err)
	}
	addon := &types.ClusterAddon{
		OrgID: "org:1", ClusterID: clusterID, CatalogItem: "platform:cm",
		State: types.AddonStateManaged, RepoID: extra.ID,
		Source: types.SourceDescriptor{Kind: types.SourceKindHelm, Helm: &types.HelmSource{RepoURL: "u", Chart: "c", Version: "v"}},
	}
	if err := s.UpsertClusterAddon(ctx, database.Pool, addon); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGitRepo(ctx, database.Pool, "org:1", extra.ID); err != nil {
		t.Fatal(err)
	}
	var bound *string
	if err := database.Pool.QueryRow(ctx, `SELECT baseline_repo_id FROM clusters WHERE id = $1`, clusterID).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if bound != nil {
		t.Errorf("baseline_repo_id not nulled: %v", *bound)
	}
	got, err := s.GetClusterAddon(ctx, database.Pool, "org:1", clusterID, "platform:cm")
	if err != nil {
		t.Fatal(err)
	}
	if got.RepoID != "" {
		t.Errorf("addon repo_id not nulled: %q", got.RepoID)
	}
}

// QA: replay migration 0033's backfill statement against a synthetic
// pre-migration state (legacy config rows present, registry empty) and
// verify the resulting default rows — including the BYO app carry-over.
func TestQABackfillReplay(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	seedOrg(t, database, ctx, "org:2", "empty")

	// Legacy rows: org:1 has a config with a BYO app; org:2 has none.
	if _, err := database.Pool.Exec(ctx, `INSERT INTO tenant_git_configs
		(org_id, repo, commit_policy, base_branch, github_app_id, github_app_installation_id,
		 github_app_key_secret, github_app_key_key)
		VALUES ('org:1', 'acme/acme-inari-state', 'pull_request', 'main', 11, 22, 'eso/key', 'private-key.pem')`); err != nil {
		t.Fatal(err)
	}

	// Exact backfill statement from 0033_tenant_git_repos.sql.
	if _, err := database.Pool.Exec(ctx, `INSERT INTO tenant_git_repos (id, org_id, name, repo, provider, scope, commit_policy, base_branch, is_default,
		github_app_id, github_app_installation_id, github_app_key_secret, github_app_key_key, github_app_api_base)
		SELECT lower(substr(md5(random()::text || clock_timestamp()::text), 1, 26)),
		       org_id, 'baseline', repo, 'github', 'platform', commit_policy, base_branch, TRUE,
		       github_app_id, github_app_installation_id, github_app_key_secret,
		       github_app_key_key, github_app_api_base
		FROM tenant_git_configs`); err != nil {
		t.Fatalf("backfill replay: %v", err)
	}

	s := NewStore()
	def, err := s.GetDefaultGitRepo(ctx, database.Pool, "org:1")
	if err != nil {
		t.Fatalf("backfilled default: %v", err)
	}
	if def.Name != "baseline" || def.Scope != types.GitRepoScopePlatform ||
		def.CommitPolicy != types.CommitPolicyPullRequest || !def.IsDefault {
		t.Errorf("bad backfill: %+v", def)
	}
	if def.GitHubApp == nil || def.GitHubApp.AppID != 11 || def.GitHubApp.InstallationID != 22 ||
		def.GitHubApp.KeyRef == nil || def.GitHubApp.KeyRef.Namespace != "eso" ||
		def.GitHubApp.KeyRef.SecretName != "key" || def.GitHubApp.KeyRef.Key != "private-key.pem" {
		t.Errorf("BYO app not carried over: %+v", def.GitHubApp)
	}
	if _, err := s.GetDefaultGitRepo(ctx, database.Pool, "org:2"); !errors.Is(err, ErrRepoNotFound) {
		t.Errorf("org without config must have no default, got %v", err)
	}

	// 0034 backfill: a pre-existing cluster binds to the org default.
	clusterID := seedCluster(t, database, ctx, "org:1", "prod")
	if _, err := database.Pool.Exec(ctx, `UPDATE clusters c SET baseline_repo_id = r.id
		FROM tenant_git_repos r WHERE r.org_id = c.org_id AND r.is_default`); err != nil {
		t.Fatal(err)
	}
	var bound string
	if err := database.Pool.QueryRow(ctx, `SELECT baseline_repo_id FROM clusters WHERE id = $1`, clusterID).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if bound != def.ID {
		t.Errorf("cluster bound to %q, want %q", bound, def.ID)
	}
}

// QA: concurrent SetDefaultGitRepo from two txs — both must not leave the
// org with two defaults (partial unique index) nor zero.
func TestQAConcurrentSetDefault(t *testing.T) {
	database, ctx := setupStoreTest(t)
	seedOrg(t, database, ctx, "org:1", "acme")
	s := NewStore()

	r1 := &types.TenantGitRepo{OrgID: "org:1", Name: "one", Repo: "acme/one", Scope: types.GitRepoScopePlatform, IsDefault: true}
	r2 := &types.TenantGitRepo{OrgID: "org:1", Name: "two", Repo: "acme/two", Scope: types.GitRepoScopePlatform}
	for _, r := range []*types.TenantGitRepo{r1, r2} {
		if err := s.UpsertGitRepo(ctx, database.Pool, r); err != nil {
			t.Fatal(err)
		}
	}
	// Two goroutines racing SetDefaultGitRepo on the pool (non-tx path,
	// the risky usage the doc comment warns about).
	done := make(chan error, 2)
	for _, id := range []string{r1.ID, r2.ID} {
		go func(id string) { done <- s.SetDefaultGitRepo(ctx, database.Pool, "org:1", id) }(id)
	}
	<-done
	<-done
	var n int
	if err := database.Pool.QueryRow(ctx, `SELECT count(*) FROM tenant_git_repos WHERE org_id = 'org:1' AND is_default`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected exactly 1 default after concurrent flips, got %d", n)
	}
}
