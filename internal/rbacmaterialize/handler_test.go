package rbacmaterialize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeTenancy struct {
	org   *types.Organization
	teams []types.Team
	roles []types.Role
	err   error
}

func (f *fakeTenancy) GetTenantByID(context.Context, string) (*types.Organization, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.org, nil
}

func (f *fakeTenancy) ListTeams(context.Context, string) ([]types.Team, error) {
	return f.teams, nil
}

func (f *fakeTenancy) ListRoles(context.Context, string) ([]types.Role, error) {
	return f.roles, nil
}

type fakeGitConfigs struct {
	cfg *types.TenantGitConfig
	err error
}

func (f *fakeGitConfigs) GitConfig(context.Context, string) (*types.TenantGitConfig, error) {
	return f.cfg, f.err
}

func event(t *testing.T, evType string, payload any) *types.OutboxEvent {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &types.OutboxEvent{EventType: evType, Payload: raw}
}

func TestHandlerEventTypes(t *testing.T) {
	h := NewHandler(&fakeTenancy{}, &fakeGitConfigs{}, gitprovider.NewFake(), nil)
	got := h.EventTypes()
	want := map[string]bool{
		types.EventRBACMappingsUpdated: true,
		types.EventTenantCreated:       true,
		types.EventTeamCreated:         true,
		types.EventTeamDeleted:         true,
		types.EventRoleCreated:         true,
		types.EventRoleUpdated:         true,
		types.EventRoleDeleted:         true,
	}
	if len(got) != len(want) {
		t.Fatalf("EventTypes = %v", got)
	}
	for _, e := range got {
		if !want[e] {
			t.Errorf("unexpected event type %q", e)
		}
	}
}

func TestHandlerCommitsRenderedRBAC(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
		teams: []types.Team{
			{Name: "admins", RoleID: "r-admin", RoleName: "admin", KeycloakGroupPath: "tenant-acme/admins"},
		},
	}, &fakeGitConfigs{}, git, nil)

	err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"}))
	if err != nil {
		t.Fatal(err)
	}
	files := git.Files("acme-inari-state", "main")
	if _, ok := files[ClusterRolesPath]; !ok {
		t.Errorf("cluster roles not committed; repo has %v", keys(files))
	}
	if _, ok := files[ClusterRoleBindingsPath]; !ok {
		t.Errorf("bindings not committed; repo has %v", keys(files))
	}
	// Repo created outside the zone flow: the root app must be seeded so
	// tenant-local ArgoCD actually syncs baseline/.
	if _, ok := files[RootAppPath]; !ok {
		t.Errorf("root app not seeded; repo has %v", keys(files))
	}
}

func TestHandlerRespectsExistingRootApp(t *testing.T) {
	git := gitprovider.NewFake()
	if _, err := git.EnsureRepo(context.Background(), "acme-inari-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := git.CommitFiles(context.Background(), "acme-inari-state", "main",
		[]gitprovider.File{{Path: RootAppPath, Content: []byte("tzf-managed")}}, "seed"); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
	}, &fakeGitConfigs{}, git, nil)
	if err := h.Handle(context.Background(), event(t, types.EventTenantCreated,
		types.TenantCreatedPayload{OrgID: "org:1", Slug: "acme"})); err != nil {
		t.Fatal(err)
	}
	if got := git.Files("acme-inari-state", "main")[RootAppPath]; got != "tzf-managed" {
		t.Errorf("root app overwritten: %q", got)
	}
}

// strictRepoFake enforces the owner/name repo contract the real github
// provider requires (splitRepo): bare repo names are rejected, exactly as
// gitprovider/github does. A plain gitprovider.Fake accepts bare names,
// which is why the bare <slug>-inari-state fallback dead-lettered only on
// live (run 423ffd13).
type strictRepoFake struct{ *gitprovider.Fake }

func (s *strictRepoFake) EnsureRepo(ctx context.Context, repo string) (string, error) {
	if !strings.Contains(repo, "/") {
		return "", fmt.Errorf("gitprovider github: invalid repo %q (want owner/name)", repo)
	}
	return s.Fake.EnsureRepo(ctx, repo)
}

func TestHandlerBareFallbackFailsAgainstOwnerQualifiedProvider(t *testing.T) {
	git := &strictRepoFake{Fake: gitprovider.NewFake()}
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
	}, &fakeGitConfigs{}, git, nil)
	err := h.Handle(context.Background(), event(t, types.EventTenantCreated,
		types.TenantCreatedPayload{OrgID: "org:1", Slug: "acme"}))
	if err == nil || !strings.Contains(err.Error(), "want owner/name") {
		t.Fatalf("bare fallback against an owner/name-enforcing provider: err = %v", err)
	}
}

func TestHandlerPrefixesStateRepoOrg(t *testing.T) {
	git := &strictRepoFake{Fake: gitprovider.NewFake()}
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
	}, &fakeGitConfigs{}, git, nil).WithStateRepoOrg("platform-org")
	if err := h.Handle(context.Background(), event(t, types.EventTenantCreated,
		types.TenantCreatedPayload{OrgID: "org:1", Slug: "acme"})); err != nil {
		t.Fatal(err)
	}
	if files := git.Files("platform-org/acme-inari-state", "main"); len(files) == 0 {
		t.Errorf("nothing committed to owner-qualified fallback repo")
	}
	if files := git.Files("acme-inari-state", "main"); len(files) != 0 {
		t.Errorf("unexpected commit to bare repo: %v", keys(files))
	}
}

func TestHandlerUsesTenantGitConfig(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
	}, &fakeGitConfigs{cfg: &types.TenantGitConfig{
		OrgID: "org:1", Repo: "custom/state", CommitPolicy: types.CommitPolicyDirect, BaseBranch: "trunk",
	}}, git, nil)
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err != nil {
		t.Fatal(err)
	}
	if files := git.Files("custom/state", "trunk"); len(files) == 0 {
		t.Errorf("nothing committed to configured repo/branch")
	}
	if files := git.Files("acme-inari-state", "main"); len(files) != 0 {
		t.Errorf("unexpected commit to default repo: %v", keys(files))
	}
}

func TestHandlerPullRequestPolicy(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
	}, &fakeGitConfigs{cfg: &types.TenantGitConfig{
		OrgID: "org:1", Repo: "acme-inari-state", CommitPolicy: types.CommitPolicyPullRequest, BaseBranch: "main",
	}}, git, nil)
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err != nil {
		t.Fatal(err)
	}
	if len(git.PRs) != 1 {
		t.Fatalf("expected 1 PR, got %d", len(git.PRs))
	}
	if files := git.Files("acme-inari-state", "main"); len(files) != 0 {
		t.Errorf("PR policy must not commit directly: %v", keys(files))
	}
}

func TestHandlerSkipsMissingOrg(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{err: tenancy.ErrOrgNotFound}, &fakeGitConfigs{}, git, nil)
	if err := h.Handle(context.Background(), event(t, types.EventTeamDeleted,
		types.TeamCreatedPayload{OrgID: "org:gone"})); err != nil {
		t.Fatalf("deleted org must be skipped, not retried: %v", err)
	}
	if files := git.Files("gone-inari-state", "main"); len(files) != 0 {
		t.Errorf("unexpected writes for missing org: %v", keys(files))
	}
}

func TestHandlerPropagatesGitErrors(t *testing.T) {
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
	}, &fakeGitConfigs{}, &failGit{Fake: gitprovider.NewFake()}, nil)
	// A git failure must surface so the dispatcher retries the event.
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err == nil {
		t.Fatal("expected git error to propagate")
	}
}

// fakeGitRepos is the registry seam fake (default row + team rows).
type fakeGitRepos struct {
	def   *types.TenantGitRepo
	teams []*types.TenantGitRepo
	err   error
}

func (f *fakeGitRepos) GetDefaultGitRepo(context.Context, string) (*types.TenantGitRepo, error) {
	return f.def, f.err
}

func (f *fakeGitRepos) ListTeamGitRepos(context.Context, string) ([]*types.TenantGitRepo, error) {
	return f.teams, f.err
}

// TestHandlerPrefersRegistryDefault pins Feature A targeting: when the
// registry has a default row, its repo/branch/policy win over the legacy
// git-config projection.
func TestHandlerPrefersRegistryDefault(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
	}, &fakeGitConfigs{cfg: &types.TenantGitConfig{
		OrgID: "org:1", Repo: "legacy/state", CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
	}}, git, nil).WithGitRepos(&fakeGitRepos{def: &types.TenantGitRepo{
		ID: "r1", OrgID: "org:1", Name: "baseline", Repo: "registry/baseline",
		Scope: types.GitRepoScopePlatform, CommitPolicy: types.CommitPolicyDirect, BaseBranch: "trunk",
		IsDefault: true,
	}})
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err != nil {
		t.Fatal(err)
	}
	if files := git.Files("registry/baseline", "trunk"); len(files) == 0 {
		t.Error("nothing committed to the registry default repo/branch")
	}
	if files := git.Files("legacy/state", "main"); len(files) != 0 {
		t.Errorf("legacy git-config repo must not be written: %v", keys(files))
	}
}

// TestHandlerRegistryDefaultPullRequest pins PR policy from the row.
func TestHandlerRegistryDefaultPullRequest(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
	}, &fakeGitConfigs{}, git, nil).WithGitRepos(&fakeGitRepos{def: &types.TenantGitRepo{
		ID: "r1", OrgID: "org:1", Name: "baseline", Repo: "acme-inari-state",
		Scope: types.GitRepoScopePlatform, CommitPolicy: types.CommitPolicyPullRequest, BaseBranch: "main",
		IsDefault: true,
	}})
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err != nil {
		t.Fatal(err)
	}
	if len(git.PRs) != 1 {
		t.Fatalf("expected 1 PR, got %d", len(git.PRs))
	}
	if files := git.Files("acme-inari-state", "main"); len(files) != 0 {
		t.Errorf("PR policy must not commit directly: %v", keys(files))
	}
}

// TestHandlerTeamRepoWritesDisabledByDefault pins the default: no team
// repos are written even when team rows exist.
func TestHandlerTeamRepoWritesDisabledByDefault(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
		teams: []types.Team{
			{ID: "t1", Name: "team-a", RoleName: "editor", KeycloakGroupPath: "tenant-acme/team-a"},
		},
	}, &fakeGitConfigs{}, git, nil).WithGitRepos(&fakeGitRepos{
		teams: []*types.TenantGitRepo{{
			ID: "r2", OrgID: "org:1", Name: "team-a", Repo: "acme/team-a-gitops",
			Scope: types.GitRepoScopeTeam, TeamID: "t1", CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
		}},
	})
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err != nil {
		t.Fatal(err)
	}
	if files := git.Files("acme/team-a-gitops", "main"); len(files) != 0 {
		t.Errorf("team repo written while team writes are disabled: %v", keys(files))
	}
}

// TestHandlerTeamRepoWrites pins the opt-in per-team path: each team-scope
// repo gets that team's bindings at teams/<team>/rbac/.
func TestHandlerTeamRepoWrites(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
		teams: []types.Team{
			{ID: "t1", Name: "team-a", RoleName: "editor", KeycloakGroupPath: "tenant-acme/team-a"},
			{ID: "t2", Name: "team-b", RoleName: "viewer", KeycloakGroupPath: "tenant-acme/team-b"},
		},
	}, &fakeGitConfigs{}, git, nil).WithGitRepos(&fakeGitRepos{
		teams: []*types.TenantGitRepo{{
			ID: "r2", OrgID: "org:1", Name: "team-a", Repo: "acme/team-a-gitops",
			Scope: types.GitRepoScopeTeam, TeamID: "t1", CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
		}},
	}).WithTeamRepoWrites()
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err != nil {
		t.Fatal(err)
	}
	// Baseline write still happened (default convention repo).
	if files := git.Files("acme-inari-state", "main"); len(files) == 0 {
		t.Error("baseline repo not written")
	}
	files := git.Files("acme/team-a-gitops", "main")
	bindings, ok := files["teams/team-a/rbac/clusterrolebindings.yaml"]
	if !ok {
		t.Fatalf("team-a bindings not committed: %v", keys(files))
	}
	if !strings.Contains(bindings, "tenant-acme-team-a-editor") {
		t.Errorf("team-a binding missing:\n%s", bindings)
	}
	if strings.Contains(bindings, "team-b") {
		t.Errorf("team-a repo must not carry team-b bindings:\n%s", bindings)
	}
}

type failGit struct{ *gitprovider.Fake }

func (f *failGit) CommitFiles(context.Context, string, string, []gitprovider.File, string) (*gitprovider.Result, error) {
	return nil, errors.New("boom")
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestHandlerTeamRepoWritesPullRequest pins the per-row policy: a team
// repo with pull_request policy gets a PR, not a direct commit.
func TestHandlerTeamRepoWritesPullRequest(t *testing.T) {
	git := gitprovider.NewFake()
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
		teams: []types.Team{
			{ID: "t1", Name: "team-a", RoleName: "editor", KeycloakGroupPath: "tenant-acme/team-a"},
		},
	}, &fakeGitConfigs{}, git, nil).WithGitRepos(&fakeGitRepos{
		teams: []*types.TenantGitRepo{{
			ID: "r2", OrgID: "org:1", Name: "team-a", Repo: "acme/team-a-gitops",
			Scope: types.GitRepoScopeTeam, TeamID: "t1", CommitPolicy: types.CommitPolicyPullRequest, BaseBranch: "main",
		}},
	}).WithTeamRepoWrites()
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err != nil {
		t.Fatal(err)
	}
	if files := git.Files("acme/team-a-gitops", "main"); len(files) != 0 {
		t.Errorf("PR-policy team repo must not be committed directly: %v", keys(files))
	}
	var sawTeamPR bool
	for _, pr := range git.PRs {
		if pr.Repo == "acme/team-a-gitops" {
			sawTeamPR = true
		}
	}
	if !sawTeamPR {
		t.Errorf("no PR opened for the team repo: %+v", git.PRs)
	}
}

// TestHandlerTeamRepoWriteFailurePropagates pins the retry contract: a
// failing team-repo write surfaces so the dispatcher retries (the baseline
// write is idempotent, so a re-drive is safe).
func TestHandlerTeamRepoWriteFailurePropagates(t *testing.T) {
	git := &failRepoGit{Fake: gitprovider.NewFake(), repo: "acme/team-a-gitops"}
	h := NewHandler(&fakeTenancy{
		org: &types.Organization{ID: "org:1", Slug: "acme", Status: "active"},
		teams: []types.Team{
			{ID: "t1", Name: "team-a", RoleName: "editor", KeycloakGroupPath: "tenant-acme/team-a"},
		},
	}, &fakeGitConfigs{}, git, nil).WithGitRepos(&fakeGitRepos{
		teams: []*types.TenantGitRepo{{
			ID: "r2", OrgID: "org:1", Name: "team-a", Repo: "acme/team-a-gitops",
			Scope: types.GitRepoScopeTeam, TeamID: "t1", CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
		}},
	}).WithTeamRepoWrites()
	if err := h.Handle(context.Background(), event(t, types.EventRBACMappingsUpdated,
		types.RBACMappingsPayload{OrgID: "org:1"})); err == nil {
		t.Fatal("expected team-repo write failure to propagate")
	}
}

// failRepoGit fails CommitFiles for one repo only (team-write error path).
type failRepoGit struct {
	*gitprovider.Fake
	repo string
}

func (f *failRepoGit) CommitFiles(ctx context.Context, repo, branch string, files []gitprovider.File, message string) (*gitprovider.Result, error) {
	if repo == f.repo {
		return nil, errors.New("boom")
	}
	return f.Fake.CommitFiles(ctx, repo, branch, files, message)
}
