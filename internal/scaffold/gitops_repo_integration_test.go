//go:build integration

package scaffold

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/gitrepos"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

// TestReconcileGitopsRepoRun drives a full kind: gitops-repo run
// end-to-end (Feature B, parent plan §5): the pipeline replaces
// creating-pipeline/registering-catalog with registering-repo (a real
// tenant_git_repos row via the registry service) and attaching-root-app
// (root Application committed to the baseline repo + RegisterArgoCDApp
// enqueued), and binding-rbac maps the existing owning team.
func TestReconcileGitopsRepoRun(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()

	// Seed: owning team (with a role row), a baseline platform repo marked
	// default, and the gitops-repo template catalog rows carrying the
	// kind in the version payload.
	if _, err := f.db.Pool.Exec(ctx, `
		INSERT INTO roles (org_id, name, display_name, builtin, permissions) VALUES
		  ('org:acme','editor','Developer',true,'["tenant.read","deployments.create"]');
		INSERT INTO teams (id, org_id, name, role_id, keycloak_group_path) SELECT
		  '11111111-1111-1111-1111-111111111111', 'org:acme', 'team-a', id, '/tenant-acme/team-a'
		  FROM roles WHERE org_id='org:acme' AND name='editor';
		INSERT INTO catalog_items (id, source, name, display_name, description) VALUES
		  ('template:gitops-repo','template','gitops-repo','GitOps Repository','Team GitOps repo');
		INSERT INTO catalog_item_versions (item_id, version, channel, schema, payload) VALUES
		  ('template:gitops-repo','1.0.0','stable','{"type":"object"}',
		   '{"manifest":{"name":"gitops-repo","version":"1.0.0","kind":"gitops-repo"}}')`); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{
		"root-application.yaml.tmpl": "kind: Application\nname: {{ .Values.repoName }}-root\n",
		"apps/README.md":             "# apps\n",
	})

	git := gitprovider.NewFake()
	reg := &fakeRegistrar{}
	rbac := &fakeRBACBinder{}
	invStore := inventory.NewStore()
	// The registry service runs against the real DB with a fake git
	// resolver; the scaffold seams consume it directly.
	repoResolver := gitprovider.NewRepoResolver(
		itRepoStore{invStore, f.db}, nil, gitprovider.StaticResolver{P: git})
	gitReposSvc := gitrepos.NewService(invStore, repoResolver, nil, audit.NewStore(), f.db)
	tenancySvc := tenancy.NewService(f.db, nil, tenancy.NewStore(), audit.NewStore())

	// The org's baseline repo exists (platform scope, default) so the
	// attach has somewhere to land.
	if _, err := git.EnsureRepo(ctx, "acme-platform/acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := gitReposSvc.Register(ctx, "org:acme", gitrepos.RegisterInput{
		Name: "baseline", Repo: "acme-platform/acme-inari-state",
		Scope: types.GitRepoScopePlatform, IsDefault: true,
	}, "dev-1"); err != nil {
		t.Fatal(err)
	}

	f.svc.WithExecEnv(&ExecEnv{
		Git: git, GitOrg: "acme-platform", Registrar: reg, RBAC: rbac,
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
		GitRepos: gitReposSvc, RootApp: gitReposSvc, Teams: tenancySvc,
	})

	run, steps, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "gitops-repo", "", "",
		json.RawMessage(`{"repoName":"team-a-gitops","team":"team-a","commitPolicy":"direct","baseBranch":"main"}`))
	if err != nil {
		t.Fatal(err)
	}
	// Kind seeding: the gitops-repo pipeline, not the component one.
	wantOrder := []string{"rendering", "creating-repo", "registering-repo", "attaching-root-app", "binding-rbac"}
	if len(steps) != len(wantOrder) {
		t.Fatalf("seeded %d steps, want %d: %+v", len(steps), len(wantOrder), steps)
	}
	for i, n := range wantOrder {
		if steps[i].Name != n {
			t.Fatalf("step %d = %q, want %q", i, steps[i].Name, n)
		}
	}

	f.svc.reconcileOnce(ctx, time.Minute)

	got, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCompleted {
		t.Fatalf("phase = %q (err %q), want completed", got.Phase, got.Error)
	}
	for i, n := range wantOrder {
		if steps[i].Name != n || steps[i].State != types.ScaffoldStepCompleted {
			t.Fatalf("step %d = %+v", i, steps[i])
		}
	}

	// creating-repo: repo named by values.repoName under the default org.
	var repoRes createRepoResult
	if err := json.Unmarshal(steps[1].Result, &repoRes); err != nil {
		t.Fatal(err)
	}
	if repoRes.RepoName != "acme-platform/team-a-gitops" {
		t.Fatalf("repoName = %q", repoRes.RepoName)
	}
	if committed := git.Files(repoRes.RepoName, "main"); committed["root-application.yaml"] == "" {
		t.Fatalf("skeleton not committed: %v", committed)
	}

	// registering-repo: a real tenant_git_repos row, team scope.
	var regRes registerRepoResult
	if err := json.Unmarshal(steps[2].Result, &regRes); err != nil {
		t.Fatal(err)
	}
	row, err := invStore.GetGitRepo(ctx, f.db.Pool, "org:acme", regRes.RepoID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Scope != types.GitRepoScopeTeam || row.TeamID != "11111111-1111-1111-1111-111111111111" ||
		row.Repo != "acme-platform/team-a-gitops" || row.Provider != types.GitRepoProviderGitHub {
		t.Fatalf("repo row = %+v", row)
	}

	// attaching-root-app: root app committed into the baseline + command.
	if committed := git.Files("acme-platform/acme-inari-state", "main"); committed["gitops-repos/team-a-gitops/root-app.yaml"] == "" {
		t.Fatalf("root app not committed to baseline: %v", committed)
	}
	if len(reg.cmds) != 1 || reg.cmds[0].ClusterID != "cluster:dev-1" {
		t.Fatalf("enqueued commands = %+v", reg.cmds)
	}

	// binding-rbac: existing team mapped, no maintainers team created.
	if len(rbac.teams) != 0 {
		t.Fatalf("gitops-repo must not create teams: %+v", rbac.teams)
	}
	if len(rbac.members) != 1 || rbac.members[0].Team != "team-a" {
		t.Fatalf("members = %+v", rbac.members)
	}

	var outputs map[string]any
	if err := json.Unmarshal(got.Outputs, &outputs); err != nil ||
		outputs["gitRepoId"] != regRes.RepoID || outputs["rootAppPath"] != "gitops-repos/team-a-gitops/root-app.yaml" {
		t.Fatalf("outputs = %s (%v)", got.Outputs, err)
	}

	// Idempotent re-drive: no new commands, no new repos.
	f.svc.reconcileOnce(ctx, time.Minute)
	if len(reg.cmds) != 1 {
		t.Fatalf("re-drive enqueued %d commands", len(reg.cmds))
	}
}

// --- gitprovider.RepoResolver seams over the test DB ---------------------

// itRepoStore adapts inventory.Store to gitprovider.RepoStore (drops the
// db.Querier — the pool is bound here).
type itRepoStore struct {
	store *inventory.Store
	db    *db.DB
}

func (a itRepoStore) GetGitRepo(ctx context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	return a.store.GetGitRepo(ctx, a.db.Pool, orgID, id)
}

func (a itRepoStore) GetDefaultGitRepo(ctx context.Context, orgID string) (*types.TenantGitRepo, error) {
	return a.store.GetDefaultGitRepo(ctx, a.db.Pool, orgID)
}
