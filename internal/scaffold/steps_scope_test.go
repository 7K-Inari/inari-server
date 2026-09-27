// Template-scope git routing (M8.W6): platform scope (the fail-safe
// default) always commits through the platform app; user scope resolves
// the initiating user's connected git identity (model C). When the user
// has no connection the tenant's userTemplateFallback policy decides:
// block (default) fails with ErrGitConnectionRequired (typed 409 +
// connect-account deep link); platform_app routes through the platform
// app and fires the OnGitFallback audit hook exactly once.
package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	gitgithub "github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider/github"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeUserGit is a programmable UserGitResolver.
type fakeUserGit struct {
	provider gitprovider.Provider
	info     *gitprovider.AuthInfo
	err      error
	calls    int
}

func (f *fakeUserGit) ForUser(_ context.Context, _, _ string) (gitprovider.Provider, *gitprovider.AuthInfo, error) {
	f.calls++
	return f.provider, f.info, f.err
}

const userScopeBlock = `  scope: user
  createRepo:
    defaultBranch: main
`

func scopeFixture(t *testing.T, scaffoldYAML string) (*RunContext, *types.ScaffoldRunStep, *ExecEnv, *countingGit, string) {
	t.Helper()
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", scaffoldYAML, map[string]string{"a.txt": "x"})
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
	rc.Run.CreatedBy = "dev-1"
	git := &countingGit{Fake: gitprovider.NewFake()}
	env := testEnv(dir, git, nil)
	return rc, repo, env, git, dir
}

func TestScopeDefaultsToPlatform(t *testing.T) {
	rc, repo, env, git, _ := scopeFixture(t, testScaffoldBlock) // no scope key
	ug := &fakeUserGit{err: &gitgithub.ErrNoConnection{OrgID: "org:acme", UserSub: "dev-1", Provider: "github"}}
	env.UserGit = ug

	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if ug.calls != 0 {
		t.Fatalf("platform scope must not resolve user git (calls=%d)", ug.calls)
	}
	if git.ensures != 1 || git.commits != 1 {
		t.Fatalf("platform git writes = %d/%d, want 1/1", git.ensures, git.commits)
	}
	if got := outputValue(rc.Run.Outputs, "authModel"); got != "platform" {
		t.Fatalf("authModel = %q, want platform", got)
	}
}

func TestScopeUserWithConnection(t *testing.T) {
	rc, repo, env, platformGit, _ := scopeFixture(t, userScopeBlock)
	userGit := &countingGit{Fake: gitprovider.NewFake()}
	env.UserGit = &fakeUserGit{
		provider: userGit,
		info:     &gitprovider.AuthInfo{Model: gitprovider.AuthModelUser, UserSub: "dev-1", ConnectionID: "ugc:1", ProviderLogin: "octocat"},
	}

	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if userGit.ensures != 1 || userGit.commits != 1 {
		t.Fatalf("user git writes = %d/%d, want 1/1", userGit.ensures, userGit.commits)
	}
	if platformGit.ensures != 0 || platformGit.commits != 0 {
		t.Fatal("user scope must not touch the platform provider")
	}
	if got := outputValue(rc.Run.Outputs, "authModel"); got != "user" {
		t.Fatalf("authModel = %q, want user", got)
	}
	if got := outputValue(rc.Run.Outputs, "gitConnectionId"); got != "ugc:1" {
		t.Fatalf("gitConnectionId = %q, want ugc:1", got)
	}
	if got := outputValue(rc.Run.Outputs, "gitProviderLogin"); got != "octocat" {
		t.Fatalf("gitProviderLogin = %q, want octocat", got)
	}
}

func TestScopeUserNoConnectionBlocks(t *testing.T) {
	rc, repo, env, git, _ := scopeFixture(t, userScopeBlock)
	env.UserGit = &fakeUserGit{err: &gitgithub.ErrNoConnection{OrgID: "org:acme", UserSub: "dev-1", Provider: "github"}}
	env.GitConfigs = fakeGitConfigs{} // no row → default block

	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if done {
		t.Fatal("block policy must fail the step")
	}
	var connReq *ErrGitConnectionRequired
	if !errors.As(err, &connReq) {
		t.Fatalf("err = %v, want ErrGitConnectionRequired", err)
	}
	wantURL := "/api/v1/tenants/acme/git-connections/github/authorize"
	if connReq.ConnectURL != wantURL {
		t.Fatalf("ConnectURL = %q, want %q", connReq.ConnectURL, wantURL)
	}
	if git.ensures != 0 || git.commits != 0 {
		t.Fatal("blocked run must not write through the platform provider")
	}
	if got := outputValue(rc.Run.Outputs, "errorCode"); got != "git_connection_required" {
		t.Fatalf("errorCode output = %q", got)
	}
	if got := outputValue(rc.Run.Outputs, "connectUrl"); got != wantURL {
		t.Fatalf("connectUrl output = %q", got)
	}
}

func TestScopeUserNoResolverBlocks(t *testing.T) {
	// No UserGit seam wired (e.g. user-git module disabled): same as no
	// connection — the policy decides, default block.
	rc, repo, env, _, _ := scopeFixture(t, userScopeBlock)
	env.GitConfigs = fakeGitConfigs{}

	_, err := stepCreatingRepo(context.Background(), env, rc, repo)
	var connReq *ErrGitConnectionRequired
	if !errors.As(err, &connReq) {
		t.Fatalf("err = %v, want ErrGitConnectionRequired", err)
	}
}

func TestScopeUserFallbackPlatformApp(t *testing.T) {
	rc, repo, env, git, _ := scopeFixture(t, userScopeBlock)
	env.UserGit = &fakeUserGit{err: &gitgithub.ErrNoConnection{OrgID: "org:acme", UserSub: "dev-1", Provider: "github"}}
	env.GitConfigs = fakeGitConfigs{
		"org:acme": {OrgID: "org:acme", Repo: "acme/inari-state", UserTemplateFallback: "platform_app"},
	}
	var fallbacks []GitFallback
	env.OnGitFallback = func(_ context.Context, _ *RunContext, fb GitFallback) error {
		fallbacks = append(fallbacks, fb)
		return nil
	}

	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if git.ensures != 1 || git.commits != 1 {
		t.Fatalf("platform git writes = %d/%d, want 1/1", git.ensures, git.commits)
	}
	if len(fallbacks) != 1 {
		t.Fatalf("fallback hook calls = %d, want 1", len(fallbacks))
	}
	if fallbacks[0].UserSub != "dev-1" || fallbacks[0].Reason != "no_connection" {
		t.Fatalf("fallback = %+v", fallbacks[0])
	}
	if got := outputValue(rc.Run.Outputs, "authModel"); got != "platform_fallback" {
		t.Fatalf("authModel = %q, want platform_fallback", got)
	}
	if got := outputValue(rc.Run.Outputs, "gitFallback"); got != "platform_app" {
		t.Fatalf("gitFallback output = %q", got)
	}
}

func TestScopeUserTokenInvalidIsHardError(t *testing.T) {
	// A revoked token mid-flight is not a "no connection" case: no silent
	// platform fallback even when the policy allows it.
	rc, repo, env, git, _ := scopeFixture(t, userScopeBlock)
	env.UserGit = &fakeUserGit{err: &gitgithub.ErrUserTokenInvalid{OrgID: "org:acme", UserSub: "dev-1", ConnectionID: "ugc:1"}}
	env.GitConfigs = fakeGitConfigs{
		"org:acme": {OrgID: "org:acme", Repo: "acme/inari-state", UserTemplateFallback: "platform_app"},
	}

	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if done || err == nil {
		t.Fatalf("done=%v err=%v, want hard failure", done, err)
	}
	var connReq *ErrGitConnectionRequired
	if errors.As(err, &connReq) {
		t.Fatal("token-invalid must not map to the connect-account flow")
	}
	if git.ensures != 0 || git.commits != 0 {
		t.Fatal("token-invalid must not fall back to the platform provider")
	}
}

func TestPayloadScope(t *testing.T) {
	if got := payloadScope(nil); got != ScopePlatform {
		t.Fatalf("empty payload scope = %q", got)
	}
	if got := payloadScope(json.RawMessage(`{"manifest":{"scaffold":{"scope":"user"}}}`)); got != ScopeUser {
		t.Fatalf("user payload scope = %q", got)
	}
	if got := payloadScope(json.RawMessage(`{"manifest":{"scaffold":{"createRepo":{}}}}`)); got != ScopePlatform {
		t.Fatalf("platform default scope = %q", got)
	}
}
