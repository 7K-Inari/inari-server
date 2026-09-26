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
			{Name: "admins", Role: types.RoleOrgAdmin, KeycloakGroupPath: "tenant-acme/admins"},
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
