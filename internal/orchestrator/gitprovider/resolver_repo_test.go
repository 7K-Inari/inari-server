package gitprovider

import (
	"context"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeRepoStore is an in-memory RepoStore for RepoResolver tests.
type fakeRepoStore struct {
	byID   map[string]*types.TenantGitRepo
	def    *types.TenantGitRepo
	getErr error
	defErr error
}

func (s *fakeRepoStore) GetGitRepo(_ context.Context, orgID, id string) (*types.TenantGitRepo, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	r, ok := s.byID[orgID+"/"+id]
	if !ok {
		return nil, errTestRepoNotFound
	}
	return r, nil
}

func (s *fakeRepoStore) GetDefaultGitRepo(_ context.Context, orgID string) (*types.TenantGitRepo, error) {
	if s.defErr != nil {
		return nil, s.defErr
	}
	if s.def == nil || s.def.OrgID != orgID {
		return nil, errTestRepoNotFound
	}
	return s.def, nil
}

var errTestRepoNotFound = errors.New("git repo not found")

// fakeOrgConfigs is an in-memory OrgGitConfigs seam.
type fakeOrgConfigs struct {
	apps map[string]*types.GitHubAppConfig
}

func (f *fakeOrgConfigs) OrgGitHubApp(_ context.Context, orgID string) (*types.GitHubAppConfig, error) {
	return f.apps[orgID], nil
}

// recordingResolver captures the merged config passed to ForTenant.
type recordingResolver struct {
	lastCfg  *types.TenantGitConfig
	provider Provider
	info     *AuthInfo
	err      error
}

func (r *recordingResolver) ForTenant(_ context.Context, cfg *types.TenantGitConfig) (Provider, *AuthInfo, error) {
	r.lastCfg = cfg
	if r.err != nil {
		return nil, nil, r.err
	}
	return r.provider, r.info, nil
}

func (r *recordingResolver) ForUser(context.Context, string, string) (Provider, *AuthInfo, error) {
	return nil, nil, ErrUserModelUnsupported
}

func repoRow(orgID, id, repo string, app *types.GitHubAppConfig) *types.TenantGitRepo {
	return &types.TenantGitRepo{
		ID: id, OrgID: orgID, Name: id, Repo: repo,
		Provider: types.GitRepoProviderGitHub, Scope: types.GitRepoScopeTeam,
		CommitPolicy: types.CommitPolicyDirect, BaseBranch: "main",
		GitHubApp: app,
	}
}

func byoApp(id int64) *types.GitHubAppConfig {
	return &types.GitHubAppConfig{
		AppID: id, InstallationID: id * 10,
		KeyRef: &types.GitHubAppSecretRef{Namespace: "ns", SecretName: "s", Key: "k"},
	}
}

func TestRepoResolverResolvesDefaultRepo(t *testing.T) {
	def := repoRow("org:1", "r1", "acme/acme-inari-state", nil)
	store := &fakeRepoStore{byID: map[string]*types.TenantGitRepo{"org:1/r1": def}, def: def}
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{Model: AuthModelPlatform}}
	rr := NewRepoResolver(store, &fakeOrgConfigs{}, rec)

	row, p, info, err := rr.ResolveRepo(context.Background(), "org:1", RepoSelectorDefault)
	if err != nil {
		t.Fatal(err)
	}
	if row != def {
		t.Fatalf("row = %v, want the default row", row)
	}
	if p == nil || info == nil {
		t.Fatal("expected provider and auth info")
	}
	if rec.lastCfg.Repo != "acme/acme-inari-state" || rec.lastCfg.OrgID != "org:1" {
		t.Fatalf("merged cfg = %+v", rec.lastCfg)
	}
	if rec.lastCfg.GitHubApp != nil {
		t.Fatalf("expected platform app (nil GitHubApp), got %+v", rec.lastCfg.GitHubApp)
	}
}

func TestRepoResolverEmptySelectorMeansDefault(t *testing.T) {
	def := repoRow("org:1", "r1", "acme/acme-inari-state", nil)
	store := &fakeRepoStore{byID: map[string]*types.TenantGitRepo{"org:1/r1": def}, def: def}
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{}}
	rr := NewRepoResolver(store, &fakeOrgConfigs{}, rec)

	if _, _, _, err := rr.ResolveRepo(context.Background(), "org:1", ""); err != nil {
		t.Fatal(err)
	}
	if rec.lastCfg.Repo != def.Repo {
		t.Fatalf("repo = %q, want default %q", rec.lastCfg.Repo, def.Repo)
	}
}

func TestRepoResolverResolvesByID(t *testing.T) {
	def := repoRow("org:1", "r1", "acme/acme-inari-state", nil)
	team := repoRow("org:1", "r2", "acme/team-a-gitops", nil)
	store := &fakeRepoStore{byID: map[string]*types.TenantGitRepo{"org:1/r1": def, "org:1/r2": team}, def: def}
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{}}
	rr := NewRepoResolver(store, &fakeOrgConfigs{}, rec)

	row, _, _, err := rr.ResolveRepo(context.Background(), "org:1", "r2")
	if err != nil {
		t.Fatal(err)
	}
	if row != team {
		t.Fatalf("row = %v, want team repo row", row)
	}
	if rec.lastCfg.Repo != "acme/team-a-gitops" {
		t.Fatalf("repo = %q", rec.lastCfg.Repo)
	}
}

func TestRepoResolverNotFoundPropagates(t *testing.T) {
	store := &fakeRepoStore{byID: map[string]*types.TenantGitRepo{}}
	rr := NewRepoResolver(store, &fakeOrgConfigs{}, &recordingResolver{})
	if _, _, _, err := rr.ResolveRepo(context.Background(), "org:1", "nope"); !errors.Is(err, errTestRepoNotFound) {
		t.Fatalf("err = %v, want not-found", err)
	}
	if _, _, _, err := rr.ResolveRepo(context.Background(), "org:1", RepoSelectorDefault); !errors.Is(err, errTestRepoNotFound) {
		t.Fatalf("default err = %v, want not-found", err)
	}
}

func TestRepoResolverPerRepoBYOWins(t *testing.T) {
	repoApp := byoApp(42)
	orgApp := byoApp(7)
	row := repoRow("org:1", "r1", "acme/team-a-gitops", repoApp)
	store := &fakeRepoStore{byID: map[string]*types.TenantGitRepo{"org:1/r1": row}, def: row}
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{Model: AuthModelBYO}}
	rr := NewRepoResolver(store, &fakeOrgConfigs{apps: map[string]*types.GitHubAppConfig{"org:1": orgApp}}, rec)

	if _, _, _, err := rr.ResolveRepo(context.Background(), "org:1", "r1"); err != nil {
		t.Fatal(err)
	}
	if rec.lastCfg.GitHubApp != repoApp {
		t.Fatalf("GitHubApp = %+v, want per-repo override", rec.lastCfg.GitHubApp)
	}
}

func TestRepoResolverOrgAppFallback(t *testing.T) {
	orgApp := byoApp(7)
	row := repoRow("org:1", "r1", "acme/team-a-gitops", nil)
	store := &fakeRepoStore{byID: map[string]*types.TenantGitRepo{"org:1/r1": row}, def: row}
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{Model: AuthModelBYO}}
	rr := NewRepoResolver(store, &fakeOrgConfigs{apps: map[string]*types.GitHubAppConfig{"org:1": orgApp}}, rec)

	if _, _, _, err := rr.ResolveRepo(context.Background(), "org:1", "r1"); err != nil {
		t.Fatal(err)
	}
	if rec.lastCfg.GitHubApp != orgApp {
		t.Fatalf("GitHubApp = %+v, want org-wide app fallback", rec.lastCfg.GitHubApp)
	}
}

func TestRepoResolverPlatformAppWhenNeitherSet(t *testing.T) {
	row := repoRow("org:1", "r1", "acme/team-a-gitops", nil)
	store := &fakeRepoStore{byID: map[string]*types.TenantGitRepo{"org:1/r1": row}, def: row}
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{Model: AuthModelPlatform}}
	rr := NewRepoResolver(store, &fakeOrgConfigs{}, rec)

	if _, _, _, err := rr.ResolveRepo(context.Background(), "org:1", "r1"); err != nil {
		t.Fatal(err)
	}
	if rec.lastCfg.GitHubApp != nil {
		t.Fatalf("GitHubApp = %+v, want nil (platform app)", rec.lastCfg.GitHubApp)
	}
}

func TestRepoResolverValidateRepo(t *testing.T) {
	row := repoRow("org:1", "r1", "acme/team-a-gitops", nil)
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{}}
	rr := NewRepoResolver(&fakeRepoStore{}, &fakeOrgConfigs{}, rec)

	// Candidate row (not yet persisted): validation works on the row itself.
	if err := rr.ValidateRepo(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	if rec.lastCfg == nil || rec.lastCfg.Repo != row.Repo {
		t.Fatalf("ValidateRepo did not resolve credentials for the row: %+v", rec.lastCfg)
	}

	wantErr := errors.New("not installed")
	rec.err = wantErr
	if err := rr.ValidateRepo(context.Background(), row); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestRepoResolverCarriesPolicyAndBranch(t *testing.T) {
	row := repoRow("org:1", "r1", "acme/team-a-gitops", nil)
	row.CommitPolicy = types.CommitPolicyPullRequest
	row.BaseBranch = "trunk"
	store := &fakeRepoStore{byID: map[string]*types.TenantGitRepo{"org:1/r1": row}, def: row}
	rec := &recordingResolver{provider: NewFake(), info: &AuthInfo{}}
	rr := NewRepoResolver(store, &fakeOrgConfigs{}, rec)

	if _, _, _, err := rr.ResolveRepo(context.Background(), "org:1", "r1"); err != nil {
		t.Fatal(err)
	}
	if rec.lastCfg.CommitPolicy != types.CommitPolicyPullRequest || rec.lastCfg.BaseBranch != "trunk" {
		t.Fatalf("merged cfg = %+v", rec.lastCfg)
	}
}
