package gitrepos

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	gitgithub "github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider/github"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeStore is an in-memory Store seam for unit tests.
type fakeStore struct {
	repos     map[string]*types.TenantGitRepo
	refCount  map[string]*types.GitRepoRefCounts
	instances map[string][]inventory.GitRepoInstanceRef
	addons    map[string][]inventory.GitRepoAddonRef
	deleted   []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		repos: map[string]*types.TenantGitRepo{}, refCount: map[string]*types.GitRepoRefCounts{},
		instances: map[string][]inventory.GitRepoInstanceRef{}, addons: map[string][]inventory.GitRepoAddonRef{},
	}
}

func (f *fakeStore) ListGitRepos(_ context.Context, _ db.Querier, orgID string, teamIDs []string) ([]*types.TenantGitRepo, error) {
	var out []*types.TenantGitRepo
	for _, r := range f.repos {
		if r.OrgID != orgID {
			continue
		}
		if len(teamIDs) == 0 || r.Scope == types.GitRepoScopePlatform || contains(teamIDs, r.TeamID) {
			out = append(out, r)
		}
	}
	return out, nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func (f *fakeStore) ListGitReposWithoutWebhook(_ context.Context, _ db.Querier) ([]*types.TenantGitRepo, error) {
	var out []*types.TenantGitRepo
	for _, r := range f.repos {
		if r.WebhookURL == "" {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeStore) FindGitRepoByRepo(_ context.Context, _ db.Querier, repo string, provider types.GitRepoProvider) (*types.TenantGitRepo, error) {
	for _, r := range f.repos {
		if strings.EqualFold(r.Repo, repo) && r.Provider == provider {
			return r, nil
		}
	}
	return nil, inventory.ErrRepoNotFound
}

func (f *fakeStore) GetGitRepo(_ context.Context, _ db.Querier, orgID, id string) (*types.TenantGitRepo, error) {
	r, ok := f.repos[id]
	if !ok || r.OrgID != orgID {
		return nil, inventory.ErrRepoNotFound
	}
	return r, nil
}

func (f *fakeStore) GetDefaultGitRepo(_ context.Context, _ db.Querier, orgID string) (*types.TenantGitRepo, error) {
	for _, r := range f.repos {
		if r.OrgID == orgID && r.IsDefault {
			return r, nil
		}
	}
	return nil, inventory.ErrRepoNotFound
}

func (f *fakeStore) UpsertGitRepo(_ context.Context, _ db.Querier, r *types.TenantGitRepo) error {
	if r.ID == "" {
		r.ID = "repo-" + r.Name
	}
	for _, ex := range f.repos {
		if ex.OrgID == r.OrgID && ex.Repo == r.Repo && ex.ID != r.ID {
			return ErrRepoConflict
		}
	}
	f.repos[r.ID] = r
	return nil
}

func (f *fakeStore) DeleteGitRepo(_ context.Context, _ db.Querier, orgID, id string) error {
	r, err := f.GetGitRepo(context.Background(), nil, orgID, id)
	if err != nil {
		return err
	}
	if r.IsDefault {
		return inventory.ErrRepoInUse
	}
	delete(f.repos, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeStore) SetDefaultGitRepo(_ context.Context, _ db.Querier, orgID, id string) error {
	if _, err := f.GetGitRepo(context.Background(), nil, orgID, id); err != nil {
		return err
	}
	for _, ex := range f.repos {
		if ex.OrgID == orgID {
			ex.IsDefault = ex.ID == id
		}
	}
	return nil
}

func (f *fakeStore) GitRepoRefCounts(_ context.Context, _ db.Querier, _, repoID string) (*types.GitRepoRefCounts, error) {
	if c, ok := f.refCount[repoID]; ok {
		return c, nil
	}
	return &types.GitRepoRefCounts{}, nil
}

func (f *fakeStore) ListGitRepoInstances(_ context.Context, _ db.Querier, _, repoID string) ([]inventory.GitRepoInstanceRef, error) {
	return f.instances[repoID], nil
}

func (f *fakeStore) ListGitRepoAddons(_ context.Context, _ db.Querier, _, repoID string) ([]inventory.GitRepoAddonRef, error) {
	return f.addons[repoID], nil
}

// Registering a repo slug already held by ANOTHER org is rejected
// (ErrRepoRegisteredElsewhere): webhook deliveries are routed per
// (lower(repo), provider) to one row's secret, so a slug lives in exactly
// one org. Same-org duplicates keep the existing ErrRepoConflict path.
func TestRegisterRejectsCrossOrgDuplicate(t *testing.T) {
	store := newFakeStore()
	store.repos["repo-foreign"] = &types.TenantGitRepo{
		ID: "repo-foreign", OrgID: "org:2", Name: "baseline", Repo: "acme/shared",
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopePlatform,
	}
	svc := NewService(store, repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil)

	_, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "shared", Repo: "acme/shared", Scope: types.GitRepoScopePlatform,
	}, "user:u1")
	if !errors.Is(err, ErrRepoRegisteredElsewhere) {
		t.Fatalf("cross-org duplicate err = %v, want ErrRepoRegisteredElsewhere", err)
	}
	// Case variants address the same git-host repo.
	_, err = svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "shared2", Repo: "ACME/SHARED", Scope: types.GitRepoScopePlatform,
	}, "user:u1")
	if !errors.Is(err, ErrRepoRegisteredElsewhere) {
		t.Fatalf("case-variant err = %v, want ErrRepoRegisteredElsewhere", err)
	}
	// Same-org duplicate: ErrRepoConflict, NOT the elsewhere sentinel.
	_, err = svc.Register(context.Background(), "org:2", RegisterInput{
		Name: "again", Repo: "acme/shared", Scope: types.GitRepoScopePlatform,
	}, "user:u1")
	if !errors.Is(err, ErrRepoConflict) || errors.Is(err, ErrRepoRegisteredElsewhere) {
		t.Fatalf("same-org duplicate err = %v, want ErrRepoConflict (not ErrRepoRegisteredElsewhere)", err)
	}
}

// fakeResolver returns a configured provider or error.
type fakeResolver struct {
	provider gitprovider.Provider
	err      error
}

func (f *fakeResolver) ForTenant(_ context.Context, _ *types.TenantGitConfig) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	return f.provider, &gitprovider.AuthInfo{Model: gitprovider.AuthModelStatic}, f.err
}

func (f *fakeResolver) ForUser(_ context.Context, _, _ string) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	return nil, nil, gitprovider.ErrUserModelUnsupported
}

// repoResolver wraps a fake credential resolver into the RepoResolver seam
// the service consumes. The service only resolves in-memory rows
// (ValidateRepo/ResolveRow/ProbeRepo), so no registry store is needed.
func repoResolver(r gitprovider.Resolver) *gitprovider.RepoResolver {
	return gitprovider.NewRepoResolver(nil, nil, r)
}

// recordingProvider records DeleteFiles paths; embeds the Fake for the rest.
type recordingProvider struct {
	*gitprovider.Fake
	deletedPaths []string
}

func (p *recordingProvider) DeleteFiles(ctx context.Context, repo, branch string, paths []string, message string) (*gitprovider.Result, error) {
	p.deletedPaths = append(p.deletedPaths, paths...)
	return p.Fake.DeleteFiles(ctx, repo, branch, paths, message)
}

func TestRegisterValidatesInput(t *testing.T) {
	svc := NewService(newFakeStore(), repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil)

	cases := []struct {
		name string
		in   RegisterInput
		want error
	}{
		{"empty name", RegisterInput{Repo: "acme/x"}, ErrInvalidInput},
		{"bad repo shape", RegisterInput{Name: "x", Repo: "noslash"}, ErrInvalidInput},
		{"unsupported provider", RegisterInput{Name: "x", Repo: "acme/x", Provider: "gitlab"}, ErrInvalidInput},
		{"team scope without team", RegisterInput{Name: "x", Repo: "acme/x", Scope: types.GitRepoScopeTeam}, ErrInvalidInput},
		{"platform scope with team", RegisterInput{Name: "x", Repo: "acme/x", Scope: types.GitRepoScopePlatform, TeamID: "t1"}, ErrInvalidInput},
		{"team scope as default", RegisterInput{Name: "x", Repo: "acme/x", Scope: types.GitRepoScopeTeam,
			TeamID: "11111111-1111-1111-1111-111111111111", IsDefault: true}, ErrInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Register(context.Background(), "org:1", tc.in, "user:u")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRegisterAppNotInstalledPropagates(t *testing.T) {
	notInstalled := &gitgithub.ErrAppNotInstalled{Org: "acme", InstallURL: "https://github.com/apps/x/installations/new"}
	svc := NewService(newFakeStore(), repoResolver(&fakeResolver{err: notInstalled}), nil, nil)

	_, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "team-a", Repo: "acme/team-a", Scope: types.GitRepoScopePlatform,
	}, "user:u")
	var got *gitgithub.ErrAppNotInstalled
	if !errors.As(err, &got) {
		t.Fatalf("err = %v (%T), want ErrAppNotInstalled", err, err)
	}
}

func TestRegisterPersistsWithDefaults(t *testing.T) {
	store := newFakeStore()
	svc := NewService(store, repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil)

	r, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true,
	}, "user:u")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if r.ID == "" || r.Provider != types.GitRepoProviderGitHub || r.CommitPolicy != types.CommitPolicyDirect || r.BaseBranch != "main" {
		t.Errorf("defaults not applied: %+v", r)
	}
	if store.repos[r.ID] == nil {
		t.Error("row not persisted")
	}

	// Duplicate repo under a different name conflicts.
	_, err = svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "other", Repo: "acme/state", Scope: types.GitRepoScopePlatform,
	}, "user:u")
	if !errors.Is(err, ErrRepoConflict) {
		t.Errorf("duplicate repo: want ErrRepoConflict, got %v", err)
	}
}

func TestUnregisterGuard(t *testing.T) {
	store := newFakeStore()
	fake := gitprovider.NewFake()
	for _, r := range []string{"acme/state", "acme/team"} {
		if _, err := fake.EnsureRepo(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewService(store, repoResolver(&fakeResolver{provider: fake}), nil, nil)

	baseline, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true,
	}, "user:u")
	if err != nil {
		t.Fatal(err)
	}
	team, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam, TeamID: "11111111-1111-1111-1111-111111111111",
	}, "user:u")
	if err != nil {
		t.Fatal(err)
	}

	// Default repo: hard block regardless of force.
	if err := svc.Unregister(context.Background(), "org:1", baseline.ID, true, UnregisterModeOrphan, "user:u"); !errors.Is(err, inventory.ErrRepoInUse) {
		t.Errorf("delete default: want ErrRepoInUse, got %v", err)
	}

	// Live refs without force: blocked with counts.
	store.refCount[team.ID] = &types.GitRepoRefCounts{Instances: 2, Addons: 1}
	err = svc.Unregister(context.Background(), "org:1", team.ID, false, "", "user:u")
	var inUse *RepoInUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("want RepoInUseError, got %v (%T)", err, err)
	}
	if inUse.Refs.Instances != 2 || inUse.Refs.Addons != 1 {
		t.Errorf("refs = %+v", inUse.Refs)
	}

	// Invalid mode rejected.
	if err := svc.Unregister(context.Background(), "org:1", team.ID, true, "bogus", "user:u"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("bad mode: want ErrInvalidInput, got %v", err)
	}

	// Forced orphan deletes despite refs.
	if err := svc.Unregister(context.Background(), "org:1", team.ID, true, UnregisterModeOrphan, "user:u"); err != nil {
		t.Fatalf("orphan: %v", err)
	}
	if len(store.deleted) != 1 || store.deleted[0] != team.ID {
		t.Errorf("deleted = %v", store.deleted)
	}
}

func TestUnregisterTeardownDeletesManifests(t *testing.T) {
	store := newFakeStore()
	fake := gitprovider.NewFake()
	if _, err := fake.EnsureRepo(context.Background(), "acme/team"); err != nil {
		t.Fatal(err)
	}
	prov := &recordingProvider{Fake: fake}
	svc := NewService(store, repoResolver(&fakeResolver{provider: prov}), nil, nil)

	team, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam, TeamID: "11111111-1111-1111-1111-111111111111",
	}, "user:u")
	if err != nil {
		t.Fatal(err)
	}
	store.refCount[team.ID] = &types.GitRepoRefCounts{Addons: 1}
	store.addons[team.ID] = []inventory.GitRepoAddonRef{
		{ID: "addon-1", ClusterID: "cluster-1", RepoPath: "addons/cert-manager", ArgoCDApp: "inari-addon-addon-1"},
	}

	if err := svc.Unregister(context.Background(), "org:1", team.ID, true, UnregisterModeTeardown, "user:u"); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if len(prov.deletedPaths) == 0 {
		t.Error("teardown did not delete manifests from repo")
	}
	if len(store.deleted) != 1 {
		t.Errorf("deleted = %v", store.deleted)
	}
}

func TestUpdatePromotesDefault(t *testing.T) {
	store := newFakeStore()
	svc := NewService(store, repoResolver(&fakeResolver{provider: gitprovider.NewFake()}), nil, nil)

	r1, _ := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true}, "user:u")
	r2, _ := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "baseline-2", Repo: "acme/state-2", Scope: types.GitRepoScopePlatform}, "user:u")

	// Explicit demote is rejected.
	if _, err := svc.Update(context.Background(), "org:1", r1.ID, PatchInput{IsDefault: boolPtr(false)}, "user:u"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("demote: want ErrInvalidInput, got %v", err)
	}

	got, err := svc.Update(context.Background(), "org:1", r2.ID, PatchInput{IsDefault: boolPtr(true)}, "user:u")
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if !got.IsDefault {
		t.Error("not promoted")
	}
	if store.repos[r1.ID].IsDefault {
		t.Error("old default not demoted")
	}

	// Policy/branch patch.
	got, err = svc.Update(context.Background(), "org:1", r2.ID, PatchInput{
		CommitPolicy: strPtr("pull_request"), BaseBranch: strPtr("trunk")}, "user:u")
	if err != nil {
		t.Fatal(err)
	}
	if got.CommitPolicy != types.CommitPolicyPullRequest || got.BaseBranch != "trunk" {
		t.Errorf("patch not applied: %+v", got)
	}
}

// TestUpdatePromoteTeamRepoRejected pins the default-slot scope guard: a
// team-scope repo can never be promoted to the org default (the
// orchestrator's team-write enforcement skips empty selectors, so a
// team-scope default would be writable by any org member).
func TestUpdatePromoteTeamRepoRejected(t *testing.T) {
	store := newFakeStore()
	fake := gitprovider.NewFake()
	for _, r := range []string{"acme/state", "acme/team"} {
		if _, err := fake.EnsureRepo(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewService(store, repoResolver(&fakeResolver{provider: fake}), nil, nil)

	if _, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true}, "user:u"); err != nil {
		t.Fatal(err)
	}
	team, err := svc.Register(context.Background(), "org:1", RegisterInput{
		Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam,
		TeamID: "11111111-1111-1111-1111-111111111111"}, "user:u")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(context.Background(), "org:1", team.ID, PatchInput{IsDefault: boolPtr(true)}, "user:u"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("promote team repo: want ErrInvalidInput, got %v", err)
	}
}

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }

// TestRegisterTeamRepoAttachesRootApp pins the Feature A attach flow
// (plan §3): registering a team-scope repo commits
// gitops-repos/<name>/root-app.yaml into the org's default baseline repo,
// pointing ArgoCD at the team repo.
func TestRegisterTeamRepoAttachesRootApp(t *testing.T) {
	store := newFakeStore()
	fake := gitprovider.NewFake()
	ctx := context.Background()
	if _, err := fake.EnsureRepo(ctx, "acme/state"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.EnsureRepo(ctx, "acme/team"); err != nil {
		t.Fatal(err)
	}
	svc := NewService(store, repoResolver(&fakeResolver{provider: fake}), nil, nil)

	if _, err := svc.Register(ctx, "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true}, "user:u"); err != nil {
		t.Fatal(err)
	}
	team, err := svc.Register(ctx, "org:1", RegisterInput{
		Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam,
		TeamID: "11111111-1111-1111-1111-111111111111"}, "user:u")
	if err != nil {
		t.Fatalf("register team repo: %v", err)
	}

	files := fake.Files("acme/state", "main")
	rootApp, ok := files["gitops-repos/team/root-app.yaml"]
	if !ok {
		t.Fatalf("root app not committed to baseline: %v", keysOfMap(files))
	}
	for _, want := range []string{"kind: Application", "acme/team", "selfHeal: true", "prune: true", "automated"} {
		if !strings.Contains(rootApp, want) {
			t.Errorf("root app missing %q:\n%s", want, rootApp)
		}
	}

	// Idempotent: re-registering (upsert) the same repo re-commits without error.
	if _, err := svc.Register(ctx, "org:1", RegisterInput{
		Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam,
		TeamID: "11111111-1111-1111-1111-111111111111"}, "user:u"); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	_ = team
}

// TestRegisterTeamRepoNoBaselineSkipsAttach pins the edge case: a team repo
// registered before any platform baseline exists succeeds without attaching
// (the root app can be attached later once a baseline exists).
func TestRegisterTeamRepoNoBaselineSkipsAttach(t *testing.T) {
	store := newFakeStore()
	fake := gitprovider.NewFake()
	ctx := context.Background()
	if _, err := fake.EnsureRepo(ctx, "acme/team"); err != nil {
		t.Fatal(err)
	}
	svc := NewService(store, repoResolver(&fakeResolver{provider: fake}), nil, nil)

	if _, err := svc.Register(ctx, "org:1", RegisterInput{
		Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam,
		TeamID: "11111111-1111-1111-1111-111111111111"}, "user:u"); err != nil {
		t.Fatalf("register without baseline: %v", err)
	}
	if len(fake.Files("acme/state", "main")) != 0 {
		t.Error("no baseline repo — nothing should have been committed")
	}
}

// TestRegisterTeamRepoSkipsAttach pins the scaffold-pipeline variant
// (Feature B): RegisterTeamRepo validates + persists the team repo but
// never commits the root app — the scaffold run's attaching-root-app step
// owns that git write.
func TestRegisterTeamRepoSkipsAttach(t *testing.T) {
	store := newFakeStore()
	fake := gitprovider.NewFake()
	ctx := context.Background()
	svc := NewService(store, repoResolver(&fakeResolver{provider: fake}), nil, nil)

	if _, err := svc.Register(ctx, "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true}, "user:u"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.EnsureRepo(ctx, "acme/state"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.EnsureRepo(ctx, "acme/team"); err != nil {
		t.Fatal(err)
	}

	row, err := svc.RegisterTeamRepo(ctx, "org:1", RegisterInput{
		Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam,
		TeamID: "11111111-1111-1111-1111-111111111111"}, "user:u")
	if err != nil {
		t.Fatalf("RegisterTeamRepo: %v", err)
	}
	if store.repos[row.ID] == nil {
		t.Fatal("row not persisted")
	}
	if got := fake.Files("acme/state", "main"); len(got) != 0 {
		t.Fatalf("RegisterTeamRepo must not attach the root app, baseline files = %v", keysOfMap(got))
	}

	// The public Register path still attaches.
	if _, err := svc.Register(ctx, "org:1", RegisterInput{
		Name: "team-2", Repo: "acme/team-2", Scope: types.GitRepoScopeTeam,
		TeamID: "11111111-1111-1111-1111-111111111111"}, "user:u"); err != nil {
		t.Fatal(err)
	}
	if got := fake.Files("acme/state", "main"); len(got) != 1 || got["gitops-repos/team-2/root-app.yaml"] == "" {
		t.Fatalf("Register must attach the root app, baseline files = %v", keysOfMap(got))
	}
}

// TestAttachRootAppFailureCompensates pins the failure path: when the
// baseline commit fails, the registration fails and the row is removed
// (best-effort compensation), so no half-registered repo is left behind.
func TestAttachRootAppFailureCompensates(t *testing.T) {
	store := newFakeStore()
	fake := gitprovider.NewFake()
	ctx := context.Background()
	// Baseline repo row exists but the fake git host has no such repo:
	// CommitFiles fails.
	svc := NewService(store, repoResolver(&fakeResolver{provider: fake}), nil, nil)

	if _, err := svc.Register(ctx, "org:1", RegisterInput{
		Name: "baseline", Repo: "acme/state", Scope: types.GitRepoScopePlatform, IsDefault: true}, "user:u"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.EnsureRepo(ctx, "acme/team"); err != nil {
		t.Fatal(err)
	}

	_, err := svc.Register(ctx, "org:1", RegisterInput{
		Name: "team", Repo: "acme/team", Scope: types.GitRepoScopeTeam,
		TeamID: "11111111-1111-1111-1111-111111111111"}, "user:u")
	if err == nil {
		t.Fatal("register succeeded despite baseline commit failure")
	}
	if len(store.repos) != 1 {
		t.Errorf("compensation: repos left = %d, want only baseline", len(store.repos))
	}
}

func keysOfMap(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
