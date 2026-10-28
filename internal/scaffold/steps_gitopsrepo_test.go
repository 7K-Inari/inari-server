package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/gitrepos"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeGitRepoRegistrar records RegisterTeamRepo calls.
type fakeGitRepoRegistrar struct {
	calls []gitrepos.RegisterInput
	row   *types.TenantGitRepo
	err   error
}

func (f *fakeGitRepoRegistrar) RegisterTeamRepo(_ context.Context, orgID string, in gitrepos.RegisterInput, actor string) (*types.TenantGitRepo, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.calls = append(f.calls, in)
	row := f.row
	if row == nil {
		row = &types.TenantGitRepo{
			ID: "repo:1", OrgID: orgID, Name: in.Name, Repo: in.Repo,
			Scope: in.Scope, TeamID: in.TeamID, CommitPolicy: in.CommitPolicy, BaseBranch: in.BaseBranch,
		}
	}
	return row, nil
}

// fakeRootAppAttacher records AttachRootApp calls.
type fakeRootAppAttacher struct {
	rows []*types.TenantGitRepo
	err  error
}

func (f *fakeRootAppAttacher) AttachRootApp(_ context.Context, orgID string, row *types.TenantGitRepo) error {
	if f.err != nil {
		return f.err
	}
	f.rows = append(f.rows, row)
	return nil
}

// fakeTeamLookup resolves teams by name.
type fakeTeamLookup struct {
	teams map[string]*types.Team
}

func (f *fakeTeamLookup) GetTeamByName(_ context.Context, slug, name string) (*types.Team, error) {
	if t, ok := f.teams[slug+"/"+name]; ok {
		return t, nil
	}
	return nil, nil
}

// gitopsFixture builds a run context for a kind: gitops-repo run with
// completed rendering/creating-repo steps and pending
// registering-repo/attaching-root-app/binding-rbac steps.
func gitopsFixture(t *testing.T, values string) (*RunContext, map[string]*types.ScaffoldRunStep) {
	t.Helper()
	run := testRun()
	run.DisplayName = "team-a-gitops"
	run.TemplateItemID = "template:gitops-repo"
	run.Values = json.RawMessage(values)
	repoResult := json.RawMessage(`{"repoName":"acme-platform/team-a-gitops","repoUrl":"https://fake.git/acme-platform/team-a-gitops.git","branch":"main","commitSha":"abc"}`)
	steps := map[string]*types.ScaffoldRunStep{
		"rendering":          {RunID: run.ID, Name: "rendering", State: types.ScaffoldStepCompleted, Result: json.RawMessage(`{"files":[]}`)},
		"creating-repo":      {RunID: run.ID, Name: "creating-repo", State: types.ScaffoldStepCompleted, Result: repoResult},
		"registering-repo":   {RunID: run.ID, Name: "registering-repo", State: types.ScaffoldStepPending, MaxAttempts: 5},
		"attaching-root-app": {RunID: run.ID, Name: "attaching-root-app", State: types.ScaffoldStepPending, MaxAttempts: 5},
		"binding-rbac":       {RunID: run.ID, Name: "binding-rbac", State: types.ScaffoldStepPending, MaxAttempts: 5},
	}
	rc := &RunContext{Run: run, Tenant: testTenant(), Actor: "dev-1", Steps: steps}
	return rc, steps
}

const gitopsValuesJSON = `{"repoName":"team-a-gitops","team":"team-a","gitOrg":"acme-platform","commitPolicy":"pull_request","baseBranch":"main"}`

func gitopsTeams() *fakeTeamLookup {
	return &fakeTeamLookup{teams: map[string]*types.Team{
		"acme/team-a": {ID: "team:team-a", OrgID: "org:acme", Name: "team-a", RoleName: "editor", KeycloakGroupPath: "tenant-acme/team-a"},
	}}
}

func TestRegisteringRepoHappyPath(t *testing.T) {
	rc, steps := gitopsFixture(t, gitopsValuesJSON)
	reg := &fakeGitRepoRegistrar{}
	env := &ExecEnv{GitRepos: reg, Teams: gitopsTeams()}

	done, err := stepRegisteringRepo(context.Background(), env, rc, steps["registering-repo"])
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(reg.calls) != 1 {
		t.Fatalf("RegisterTeamRepo calls = %d", len(reg.calls))
	}
	in := reg.calls[0]
	if in.Name != "team-a-gitops" || in.Repo != "acme-platform/team-a-gitops" {
		t.Fatalf("input name/repo = %q/%q", in.Name, in.Repo)
	}
	if in.Scope != types.GitRepoScopeTeam || in.TeamID != "team:team-a" {
		t.Fatalf("scope/team = %q/%q", in.Scope, in.TeamID)
	}
	if in.CommitPolicy != types.CommitPolicyPullRequest || in.BaseBranch != "main" {
		t.Fatalf("policy/branch = %q/%q", in.CommitPolicy, in.BaseBranch)
	}
	if in.Provider != string(types.GitRepoProviderGitHub) {
		t.Fatalf("provider = %q", in.Provider)
	}
	var res registerRepoResult
	if err := json.Unmarshal(steps["registering-repo"].Result, &res); err != nil || res.RepoID != "repo:1" {
		t.Fatalf("step result = %s (%v)", steps["registering-repo"].Result, err)
	}
	var outputs map[string]any
	if err := json.Unmarshal(rc.Run.Outputs, &outputs); err != nil || outputs["gitRepoId"] != "repo:1" {
		t.Fatalf("outputs = %s (%v)", rc.Run.Outputs, err)
	}
}

func TestRegisteringRepoIdempotentReentry(t *testing.T) {
	rc, steps := gitopsFixture(t, gitopsValuesJSON)
	steps["registering-repo"].Result = json.RawMessage(`{"repoId":"repo:1","repo":"acme-platform/team-a-gitops","teamId":"team:team-a"}`)
	reg := &fakeGitRepoRegistrar{}

	done, err := stepRegisteringRepo(context.Background(), &ExecEnv{GitRepos: reg, Teams: gitopsTeams()}, rc, steps["registering-repo"])
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(reg.calls) != 0 {
		t.Fatalf("re-entry registered %d repos", len(reg.calls))
	}
}

func TestRegisteringRepoUnknownTeamFails(t *testing.T) {
	rc, steps := gitopsFixture(t, `{"repoName":"team-a-gitops","team":"no-such-team"}`)
	reg := &fakeGitRepoRegistrar{}

	_, err := stepRegisteringRepo(context.Background(), &ExecEnv{GitRepos: reg, Teams: gitopsTeams()}, rc, steps["registering-repo"])
	if err == nil {
		t.Fatal("unknown team must fail the step")
	}
	if !strings.Contains(err.Error(), "no-such-team") {
		t.Fatalf("error should name the team: %v", err)
	}
	if len(reg.calls) != 0 {
		t.Fatal("unknown team hit the registrar")
	}
}

func TestRegisteringRepoGuards(t *testing.T) {
	rc, steps := gitopsFixture(t, gitopsValuesJSON)

	if _, err := stepRegisteringRepo(context.Background(), &ExecEnv{Teams: gitopsTeams()}, rc, steps["registering-repo"]); err == nil {
		t.Fatal("nil registrar must fail")
	}
	bare := &RunContext{Run: rc.Run, Steps: map[string]*types.ScaffoldRunStep{}, Tenant: rc.Tenant}
	if _, err := stepRegisteringRepo(context.Background(), &ExecEnv{GitRepos: &fakeGitRepoRegistrar{}, Teams: gitopsTeams()}, bare, steps["registering-repo"]); err == nil {
		t.Fatal("missing creating-repo result must fail")
	}
}

func TestRegisteringRepoTransientErrorRetry(t *testing.T) {
	rc, steps := gitopsFixture(t, gitopsValuesJSON)
	reg := &fakeGitRepoRegistrar{err: errors.New("db down")}
	env := &ExecEnv{GitRepos: reg, Teams: gitopsTeams()}

	if _, err := stepRegisteringRepo(context.Background(), env, rc, steps["registering-repo"]); err == nil {
		t.Fatal("first attempt must surface the error")
	}
	if len(steps["registering-repo"].Result) != 0 {
		t.Fatalf("failed attempt wrote a result: %s", steps["registering-repo"].Result)
	}
	reg.err = nil
	done, err := stepRegisteringRepo(context.Background(), env, rc, steps["registering-repo"])
	if err != nil || !done || len(reg.calls) != 1 {
		t.Fatalf("retry: done=%v err=%v calls=%d", done, err, len(reg.calls))
	}
}

func TestAttachingRootAppHappyPath(t *testing.T) {
	rc, steps := gitopsFixture(t, gitopsValuesJSON)
	steps["registering-repo"].State = types.ScaffoldStepCompleted
	steps["registering-repo"].Result = json.RawMessage(`{"repoId":"repo:1","repo":"acme-platform/team-a-gitops","teamId":"team:team-a"}`)
	att := &fakeRootAppAttacher{}
	reg := &fakeRegistrar{}
	env := &ExecEnv{RootApp: att, Registrar: reg}

	done, err := stepAttachingRootApp(context.Background(), env, rc, steps["attaching-root-app"])
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(att.rows) != 1 {
		t.Fatalf("AttachRootApp calls = %d", len(att.rows))
	}
	row := att.rows[0]
	if row.Name != "team-a-gitops" || row.Repo != "acme-platform/team-a-gitops" || row.BaseBranch != "main" {
		t.Fatalf("attach row = %+v", row)
	}
	if len(reg.cmds) != 1 {
		t.Fatalf("enqueued commands = %d", len(reg.cmds))
	}
	cmd := reg.cmds[0]
	if cmd.ID != "register-argocd-app:"+rc.Run.ID || cmd.ClusterID != "cluster:dev-1" {
		t.Fatalf("command = %+v", cmd)
	}
	var res attachRootAppResult
	if err := json.Unmarshal(steps["attaching-root-app"].Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.RootAppPath != "gitops-repos/team-a-gitops/root-app.yaml" || res.ApplicationName != "team-a-gitops-root" {
		t.Fatalf("result = %+v", res)
	}
	var outputs map[string]any
	if err := json.Unmarshal(rc.Run.Outputs, &outputs); err != nil || outputs["rootAppPath"] != res.RootAppPath {
		t.Fatalf("outputs = %s (%v)", rc.Run.Outputs, err)
	}
}

func TestAttachingRootAppIdempotentReentry(t *testing.T) {
	rc, steps := gitopsFixture(t, gitopsValuesJSON)
	steps["attaching-root-app"].Result = json.RawMessage(`{"rootAppPath":"gitops-repos/team-a-gitops/root-app.yaml","applicationName":"team-a-gitops-root","clusterId":"cluster:dev-1"}`)
	att := &fakeRootAppAttacher{}
	reg := &fakeRegistrar{}

	done, err := stepAttachingRootApp(context.Background(), &ExecEnv{RootApp: att, Registrar: reg}, rc, steps["attaching-root-app"])
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(att.rows) != 0 || len(reg.cmds) != 0 {
		t.Fatalf("re-entry hit seams: attaches=%d cmds=%d", len(att.rows), len(reg.cmds))
	}
}

func TestAttachingRootAppGuards(t *testing.T) {
	rc, steps := gitopsFixture(t, gitopsValuesJSON)
	steps["registering-repo"].State = types.ScaffoldStepCompleted
	steps["registering-repo"].Result = json.RawMessage(`{"repoId":"repo:1","repo":"acme-platform/team-a-gitops","teamId":"team:team-a"}`)

	if _, err := stepAttachingRootApp(context.Background(), &ExecEnv{Registrar: &fakeRegistrar{}}, rc, steps["attaching-root-app"]); err == nil {
		t.Fatal("nil root-app attacher must fail")
	}
	if _, err := stepAttachingRootApp(context.Background(), &ExecEnv{RootApp: &fakeRootAppAttacher{}}, rc, steps["attaching-root-app"]); err == nil {
		t.Fatal("nil registrar must fail")
	}
	noCluster := &RunContext{Run: rc.Run, Steps: rc.Steps, Tenant: &TenantContext{Slug: "acme", OrgID: "org:acme"}}
	if _, err := stepAttachingRootApp(context.Background(), &ExecEnv{RootApp: &fakeRootAppAttacher{}, Registrar: &fakeRegistrar{}}, noCluster, steps["attaching-root-app"]); err == nil {
		t.Fatal("missing cluster must fail")
	}
	bare := &RunContext{Run: rc.Run, Steps: map[string]*types.ScaffoldRunStep{}, Tenant: rc.Tenant}
	if _, err := stepAttachingRootApp(context.Background(), &ExecEnv{RootApp: &fakeRootAppAttacher{}, Registrar: &fakeRegistrar{}}, bare, steps["attaching-root-app"]); err == nil {
		t.Fatal("missing creating-repo result must fail")
	}
}

// --- creating-repo / binding-rbac kind branches --------------------------

// writeGitopsTemplate materializes a kind: gitops-repo template package.
func writeGitopsTemplate(t *testing.T, root, name, version string, skeleton map[string]string) {
	t.Helper()
	writeFixtureTemplate(t, root, name, version, skeleton)
	manifest := "name: " + name + "\nversion: " + version + "\nkind: gitops-repo\nscaffold:\n  createRepo:\n    defaultBranch: main\n"
	if err := os.WriteFile(filepath.Join(root, name, "template.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

// gitopsRepoFixture builds a run context with a completed rendering step
// and a pending creating-repo step for a kind: gitops-repo run.
func gitopsRepoFixture(t *testing.T, values string) (*RunContext, *types.ScaffoldRunStep) {
	t.Helper()
	run := testRun()
	run.DisplayName = "team-a-gitops"
	run.TemplateItemID = "template:gitops-repo"
	run.TemplateVersion = "1.0.0"
	run.Values = json.RawMessage(values)
	rendered, err := json.Marshal(renderResult{Files: []RenderedFile{
		{Path: "root-application.yaml", Content: "kind: Application"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	rendering := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepCompleted, Result: rendered}
	repo := &types.ScaffoldRunStep{RunID: run.ID, Name: "creating-repo", State: types.ScaffoldStepPending, MaxAttempts: 5}
	rc := &RunContext{
		Run: run, Tenant: testTenant(), Actor: "dev-1",
		Steps: map[string]*types.ScaffoldRunStep{"rendering": rendering, "creating-repo": repo},
	}
	return rc, repo
}

// The gitops-repo repo is named by values.repoName (not
// <slug>-<component>) and values.gitOrg overrides the env git org.
func TestCreatingRepoGitopsKind(t *testing.T) {
	dir := t.TempDir()
	writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{"a.txt": "x"})
	rc, repo := gitopsRepoFixture(t, gitopsValuesJSON)
	git := &countingGit{Fake: gitprovider.NewFake()}

	done, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil {
		t.Fatalf("step result: %v", err)
	}
	if res.RepoName != "acme-platform/team-a-gitops" {
		t.Fatalf("repoName = %q", res.RepoName)
	}
	if res.Branch != "main" {
		t.Fatalf("branch = %q", res.Branch)
	}
	files := git.Files(res.RepoName, "main")
	if files["root-application.yaml"] != "kind: Application" {
		t.Fatalf("committed files = %v", files)
	}
}

// Without values.gitOrg the env/tenant git org applies.
func TestCreatingRepoGitopsKindDefaultGitOrg(t *testing.T) {
	dir := t.TempDir()
	writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{"a.txt": "x"})
	rc, repo := gitopsRepoFixture(t, `{"repoName":"team-b-gitops","team":"team-b"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}

	done, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.RepoName != "inari-apps/team-b-gitops" {
		t.Fatalf("repoName = %q", res.RepoName)
	}
}

// values.baseBranch overrides the manifest defaultBranch for gitops-repo.
func TestCreatingRepoGitopsKindBaseBranchOverride(t *testing.T) {
	dir := t.TempDir()
	writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{"a.txt": "x"})
	rc, repo := gitopsRepoFixture(t, `{"repoName":"team-b-gitops","team":"team-b","baseBranch":"trunk"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}

	done, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Branch != "trunk" {
		t.Fatalf("branch = %q", res.Branch)
	}
}

// repoName is validated as a single safe path segment.
func TestCreatingRepoGitopsKindRejectsBadRepoName(t *testing.T) {
	dir := t.TempDir()
	writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{"a.txt": "x"})
	rc, repo := gitopsRepoFixture(t, `{"repoName":"../escape","team":"team-b"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}

	if _, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo); err == nil {
		t.Fatal("path-traversal repoName must fail")
	}
	if git.ensures != 0 {
		t.Fatal("invalid repoName hit git")
	}
}

// The wizard's gitOrg override is user input interpolated into the repo
// slug: multi-segment owners, traversal, spaces and other non-owner strings
// must be rejected before any git call.
func TestCreatingRepoGitopsKindRejectsBadGitOrg(t *testing.T) {
	cases := map[string]string{
		"multi-segment":  `{"repoName":"team-b-gitops","team":"team-b","gitOrg":"a/b"}`,
		"traversal":      `{"repoName":"team-b-gitops","team":"team-b","gitOrg":".."}`,
		"space":          `{"repoName":"team-b-gitops","team":"team-b","gitOrg":"evil org"}`,
		"leading hyphen": `{"repoName":"team-b-gitops","team":"team-b","gitOrg":"-evil"}`,
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{"a.txt": "x"})
			rc, repo := gitopsRepoFixture(t, values)
			git := &countingGit{Fake: gitprovider.NewFake()}

			if _, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo); err == nil {
				t.Fatal("invalid gitOrg must fail")
			}
			if git.ensures != 0 {
				t.Fatal("invalid gitOrg hit git")
			}
		})
	}
}

// The wizard's baseBranch override must satisfy git refname rules before it
// reaches the provider.
func TestCreatingRepoGitopsKindRejectsBadBaseBranch(t *testing.T) {
	cases := map[string]string{
		"dot-dot":        `{"repoName":"team-b-gitops","team":"team-b","baseBranch":"../../x"}`,
		"space":          `{"repoName":"team-b-gitops","team":"team-b","baseBranch":"branch with spaces"}`,
		"leading dot":    `{"repoName":"team-b-gitops","team":"team-b","baseBranch":".hidden"}`,
		"trailing slash": `{"repoName":"team-b-gitops","team":"team-b","baseBranch":"main/"}`,
		"lock suffix":    `{"repoName":"team-b-gitops","team":"team-b","baseBranch":"main.lock"}`,
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{"a.txt": "x"})
			rc, repo := gitopsRepoFixture(t, values)
			git := &countingGit{Fake: gitprovider.NewFake()}

			if _, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo); err == nil {
				t.Fatal("invalid baseBranch must fail")
			}
			if git.ensures != 0 {
				t.Fatal("invalid baseBranch hit git")
			}
		})
	}
}

// binding-rbac for kind: gitops-repo maps the existing owning team from
// the wizard (no <component>-maintainers team is created).
func TestBindingRBACGitopsKind(t *testing.T) {
	dir := t.TempDir()
	writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{"a.txt": "x"})
	rc, steps := gitopsFixture(t, gitopsValuesJSON)
	rc.Run.CreatedBy = "user:dev-1"
	b := &fakeRBACBinder{}
	env := &ExecEnv{RBAC: b, Teams: gitopsTeams(), Templates: &FilePuller{Root: dir}}

	done, err := stepBindingRBAC(context.Background(), env, rc, steps["binding-rbac"])
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(b.teams) != 0 {
		t.Fatalf("gitops-repo must not create teams: %+v", b.teams)
	}
	// The creator must NOT be joined into the pre-existing owning team —
	// joining would let anyone with deployments.create add themselves to any
	// team by running the gitops-repo template against it.
	if len(b.members) != 0 {
		t.Fatalf("gitops-repo must not join the creator into the owning team: %+v", b.members)
	}
	var res bindRBACResult
	if err := json.Unmarshal(steps["binding-rbac"].Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.TeamID != "team:team-a" || res.TeamName != "team-a" ||
		res.GroupPath != "tenant-acme/team-a" || res.Member != "" {
		t.Fatalf("result = %+v", res)
	}
}

func TestBindingRBACGitopsKindUnknownTeam(t *testing.T) {
	dir := t.TempDir()
	writeGitopsTemplate(t, dir, "gitops-repo", "1.0.0", map[string]string{"a.txt": "x"})
	rc, steps := gitopsFixture(t, `{"repoName":"team-a-gitops","team":"no-such-team"}`)
	b := &fakeRBACBinder{}

	_, err := stepBindingRBAC(context.Background(), &ExecEnv{RBAC: b, Teams: gitopsTeams(), Templates: &FilePuller{Root: dir}}, rc, steps["binding-rbac"])
	if err == nil {
		t.Fatal("unknown owning team must fail")
	}
	if len(b.teams) != 0 || len(b.members) != 0 {
		t.Fatal("unknown team hit the binder")
	}
}

func TestAttachingRootAppTransientErrorRetry(t *testing.T) {
	rc, steps := gitopsFixture(t, gitopsValuesJSON)
	steps["registering-repo"].State = types.ScaffoldStepCompleted
	steps["registering-repo"].Result = json.RawMessage(`{"repoId":"repo:1","repo":"acme-platform/team-a-gitops","teamId":"team:team-a"}`)
	att := &fakeRootAppAttacher{err: errors.New("git host 503")}
	reg := &fakeRegistrar{}
	env := &ExecEnv{RootApp: att, Registrar: reg}

	if _, err := stepAttachingRootApp(context.Background(), env, rc, steps["attaching-root-app"]); err == nil {
		t.Fatal("first attempt must surface the error")
	}
	if len(steps["attaching-root-app"].Result) != 0 {
		t.Fatalf("failed attempt wrote a result: %s", steps["attaching-root-app"].Result)
	}
	att.err = nil
	done, err := stepAttachingRootApp(context.Background(), env, rc, steps["attaching-root-app"])
	if err != nil || !done {
		t.Fatalf("retry: done=%v err=%v", done, err)
	}
	if len(att.rows) != 1 || len(reg.cmds) != 1 {
		t.Fatalf("attaches=%d cmds=%d", len(att.rows), len(reg.cmds))
	}
}
