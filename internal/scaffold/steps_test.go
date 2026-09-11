package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// writeScaffoldTemplate materializes a template package with a scaffold
// block (writeFixtureTemplate writes manifests without one).
func writeScaffoldTemplate(t *testing.T, root, name, version, scaffoldYAML string, skeleton map[string]string) {
	t.Helper()
	writeFixtureTemplate(t, root, name, version, skeleton)
	manifest := "name: " + name + "\nversion: " + version + "\nscaffold:\n" + scaffoldYAML
	if err := os.WriteFile(filepath.Join(root, name, "template.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testTenant() *TenantContext {
	return &TenantContext{
		Slug: "acme", OrgID: "org:acme", Namespace: "acme",
		GroupPath: "tenant-acme/members", ClusterID: "cluster:dev-1",
	}
}

// stepsFixture builds a run + steps where rendering already completed with
// one rendered file.
func stepsFixture(t *testing.T, values string) (*RunContext, *types.ScaffoldRunStep, *types.ScaffoldRunStep) {
	t.Helper()
	run := testRun()
	run.DisplayName = "payments-api"
	run.Values = json.RawMessage(values)
	rendered, err := json.Marshal(renderResult{Files: []RenderedFile{
		{Path: "k8s/deployment.yaml", Content: "kind: Deployment"},
		{Path: ".github/workflows/ci.yaml", Content: "name: ci"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	rendering := &types.ScaffoldRunStep{RunID: run.ID, Name: "rendering", State: types.ScaffoldStepCompleted, Result: rendered}
	repo := &types.ScaffoldRunStep{RunID: run.ID, Name: "creating-repo", State: types.ScaffoldStepPending, MaxAttempts: 5}
	pipeline := &types.ScaffoldRunStep{RunID: run.ID, Name: "creating-pipeline", State: types.ScaffoldStepPending, MaxAttempts: 5}
	rc := &RunContext{
		Run: run, Tenant: testTenant(), Actor: "dev-1",
		Steps: map[string]*types.ScaffoldRunStep{
			"rendering": rendering, "creating-repo": repo, "creating-pipeline": pipeline,
		},
	}
	return rc, repo, pipeline
}

// countingGit wraps gitprovider.Fake recording EnsureRepo/CommitFiles calls
// and can fail the next CommitFiles (transient error retry tests).
type countingGit struct {
	*gitprovider.Fake
	ensures  int
	commits  int
	failNext bool
}

func (g *countingGit) EnsureRepo(ctx context.Context, repo string) (string, error) {
	g.ensures++
	return g.Fake.EnsureRepo(ctx, repo)
}

func (g *countingGit) CommitFiles(ctx context.Context, repo, branch string, files []gitprovider.File, message string) (*gitprovider.Result, error) {
	g.commits++
	if g.failNext {
		g.failNext = false
		return nil, errors.New("git host 503")
	}
	return g.Fake.CommitFiles(ctx, repo, branch, files, message)
}

// fakeRegistrar captures enqueued commands and can fail the next Enqueue.
type fakeRegistrar struct {
	cmds     []*types.AgentCommand
	failNext bool
}

func (r *fakeRegistrar) Enqueue(_ context.Context, cmd *types.AgentCommand) error {
	if r.failNext {
		r.failNext = false
		return errors.New("queue unavailable")
	}
	r.cmds = append(r.cmds, cmd)
	return nil
}

const testScaffoldBlock = `  createRepo:
    defaultBranch: main
  createPipeline:
    provider: github-actions
`

func testEnv(dir string, git GitProvider, reg AppRegistrar) *ExecEnv {
	return &ExecEnv{
		Git: git, GitOrg: "inari-apps", Registrar: reg,
		Templates: &FilePuller{Root: dir},
	}
}

func TestCreatingRepoHappyPath(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", testScaffoldBlock, map[string]string{"a.txt": "x"})
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}

	done, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil {
		t.Fatalf("step result: %v", err)
	}
	if res.RepoName != "inari-apps/acme-payments-api" {
		t.Fatalf("repoName = %q", res.RepoName)
	}
	if res.RepoURL == "" || res.CommitSHA == "" || res.Branch != "main" {
		t.Fatalf("result = %+v", res)
	}
	files := git.Files(res.RepoName, "main")
	if len(files) != 2 || files["k8s/deployment.yaml"] != "kind: Deployment" {
		t.Fatalf("committed files = %v", files)
	}
	var outputs map[string]any
	if err := json.Unmarshal(rc.Run.Outputs, &outputs); err != nil || outputs["repoUrl"] != res.RepoURL {
		t.Fatalf("outputs = %s (%v)", rc.Run.Outputs, err)
	}
}

func TestCreatingRepoIdempotentReentry(t *testing.T) {
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
	repo.Result = json.RawMessage(`{"repoName":"inari-apps/acme-payments-api","repoUrl":"https://fake.git/x.git","branch":"main","commitSha":"abc"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}

	done, err := stepCreatingRepo(context.Background(), &ExecEnv{Git: git, GitOrg: "inari-apps"}, rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if git.ensures != 0 || git.commits != 0 {
		t.Fatalf("re-entry hit git: ensures=%d commits=%d", git.ensures, git.commits)
	}
}

func TestCreatingRepoTransientErrorRetry(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", testScaffoldBlock, map[string]string{"a.txt": "x"})
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
	git := &countingGit{Fake: gitprovider.NewFake(), failNext: true}
	env := testEnv(dir, git, nil)

	if _, err := stepCreatingRepo(context.Background(), env, rc, repo); err == nil {
		t.Fatal("first attempt must surface the transient error")
	}
	if len(repo.Result) != 0 {
		t.Fatalf("failed attempt wrote a result: %s", repo.Result)
	}
	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if err != nil || !done {
		t.Fatalf("retry: done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil || res.RepoURL == "" {
		t.Fatalf("retry result = %s (%v)", repo.Result, err)
	}
}

func TestCreatingRepoGuards(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", testScaffoldBlock, map[string]string{"a.txt": "x"})
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)

	if _, err := stepCreatingRepo(context.Background(), testEnv(dir, nil, nil), rc, repo); err == nil {
		t.Fatal("nil git must fail")
	}
	env := testEnv(dir, gitprovider.NewFake(), nil)
	env.GitOrg = ""
	if _, err := stepCreatingRepo(context.Background(), env, rc, repo); err == nil {
		t.Fatal("empty git org must fail")
	}
	bare := &RunContext{Run: rc.Run, Steps: map[string]*types.ScaffoldRunStep{}, Tenant: rc.Tenant}
	if _, err := stepCreatingRepo(context.Background(), testEnv(dir, gitprovider.NewFake(), nil), bare, repo); err == nil {
		t.Fatal("missing rendering result must fail")
	}
}

func TestComponentNameFallbackAndSanitization(t *testing.T) {
	cases := []struct {
		name        string
		values      string
		displayName string
		want        string
		wantErr     bool
	}{
		{name: "values.name wins", values: `{"name":"Payments API","serviceName":"other"}`, displayName: "disp", want: "payments-api"},
		{name: "serviceName fallback", values: `{"serviceName":"Orders.API"}`, displayName: "disp", want: "orders-api"},
		{name: "empty name falls through", values: `{"name":""}`, displayName: "My Comp!", want: "my-comp"},
		{name: "display name fallback", values: `{}`, displayName: "Widget", want: "widget"},
		{name: "non-string name ignored", values: `{"name":42}`, displayName: "widget", want: "widget"},
		{name: "unslugifiable name errors", values: `{"name":"!!!"}`, wantErr: true},
		{name: "no name anywhere errors", values: `{}`, wantErr: true},
		{name: "invalid values json falls back", values: `{`, displayName: "widget", want: "widget"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := testRun()
			run.DisplayName = tc.displayName
			run.Values = json.RawMessage(tc.values)
			got, err := componentName(&RunContext{Run: run})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q err %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestCreatingRepoManifestNameOverride(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0",
		"  createRepo:\n    name: custom-repo\n    defaultBranch: trunk\n", map[string]string{"a.txt": "x"})
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}

	done, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.RepoName != "inari-apps/custom-repo" || res.Branch != "trunk" {
		t.Fatalf("result = %+v", res)
	}
	if files := git.Files(res.RepoName, "trunk"); len(files) != 2 {
		t.Fatalf("committed files on trunk = %v", files)
	}
}

func TestCreatingRepoRejectsUnsafeManifestName(t *testing.T) {
	for _, bad := range []string{"..", ".", "a/b", "/abs", `a\b`} {
		dir := t.TempDir()
		writeScaffoldTemplate(t, dir, "go-service", "1.0.0",
			"  createRepo:\n    name: "+bad+"\n", map[string]string{"a.txt": "x"})
		rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
		git := &countingGit{Fake: gitprovider.NewFake()}

		if _, err := stepCreatingRepo(context.Background(), testEnv(dir, git, nil), rc, repo); err == nil {
			t.Fatalf("createRepo.name %q must fail", bad)
		}
		if git.ensures != 0 {
			t.Fatalf("createRepo.name %q hit git before validation", bad)
		}
	}
}

func TestCreatingPipelineHappyPath(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", testScaffoldBlock, map[string]string{"a.txt": "x"})
	rc, repo, pipeline := stepsFixture(t, `{"name":"payments-api"}`)
	repo.State = types.ScaffoldStepCompleted
	repo.Result = json.RawMessage(`{"repoName":"inari-apps/acme-payments-api","repoUrl":"https://fake.git/inari-apps/acme-payments-api.git","branch":"main","commitSha":"abc"}`)
	reg := &fakeRegistrar{}

	done, err := stepCreatingPipeline(context.Background(), testEnv(dir, gitprovider.NewFake(), reg), rc, pipeline)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(reg.cmds) != 1 {
		t.Fatalf("enqueued %d commands, want 1", len(reg.cmds))
	}
	cmd := reg.cmds[0]
	if cmd.ID != "register-argocd-app:"+rc.Run.ID || cmd.ClusterID != "cluster:dev-1" {
		t.Fatalf("command = %+v", cmd)
	}
	var wrapped anypb.Any
	if err := protojson.Unmarshal(cmd.Payload, &wrapped); err != nil {
		t.Fatal(err)
	}
	app := &agentv1.RegisterArgoCDApp{}
	if err := wrapped.UnmarshalTo(app); err != nil {
		t.Fatal(err)
	}
	if app.CommandId != rc.Run.ID || app.Name != "inari-payments-api" {
		t.Fatalf("app = %+v", app)
	}
	if app.Source.RepoUrl != "https://fake.git/inari-apps/acme-payments-api.git" ||
		app.Source.Path != "k8s" || app.Source.TargetRevision != "main" {
		t.Fatalf("source = %+v", app.Source)
	}
	if app.DestinationNamespace != "acme--payments-api" || app.SyncPolicy == nil || !app.SyncPolicy.Automated {
		t.Fatalf("dest/sync = %q %+v", app.DestinationNamespace, app.SyncPolicy)
	}
	var res createPipelineResult
	if err := json.Unmarshal(pipeline.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.ApplicationName != "inari-payments-api" || res.PipelineURL != "https://fake.git/inari-apps/acme-payments-api/actions" {
		t.Fatalf("result = %+v", res)
	}
	var outputs map[string]any
	if err := json.Unmarshal(rc.Run.Outputs, &outputs); err != nil || outputs["pipelineUrl"] != res.PipelineURL {
		t.Fatalf("outputs = %s (%v)", rc.Run.Outputs, err)
	}
}

func TestCreatingPipelineIdempotentReentry(t *testing.T) {
	rc, _, pipeline := stepsFixture(t, `{"name":"payments-api"}`)
	pipeline.Result = json.RawMessage(`{"applicationName":"inari-payments-api","pipelineUrl":"https://x/actions","clusterId":"cluster:dev-1"}`)
	reg := &fakeRegistrar{}

	done, err := stepCreatingPipeline(context.Background(), &ExecEnv{Registrar: reg}, rc, pipeline)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if len(reg.cmds) != 0 {
		t.Fatalf("re-entry enqueued: %v", reg.cmds)
	}
}

func TestCreatingPipelineTransientErrorRetry(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", testScaffoldBlock, map[string]string{"a.txt": "x"})
	rc, repo, pipeline := stepsFixture(t, `{"name":"payments-api"}`)
	repo.State = types.ScaffoldStepCompleted
	repo.Result = json.RawMessage(`{"repoName":"r","repoUrl":"https://fake.git/r.git","branch":"main","commitSha":"abc"}`)
	reg := &fakeRegistrar{failNext: true}
	env := testEnv(dir, gitprovider.NewFake(), reg)

	if _, err := stepCreatingPipeline(context.Background(), env, rc, pipeline); err == nil {
		t.Fatal("first attempt must surface the transient error")
	}
	done, err := stepCreatingPipeline(context.Background(), env, rc, pipeline)
	if err != nil || !done || len(reg.cmds) != 1 {
		t.Fatalf("retry: done=%v err=%v cmds=%d", done, err, len(reg.cmds))
	}
}

func TestCreatingPipelineGuards(t *testing.T) {
	rc, repo, pipeline := stepsFixture(t, `{"name":"payments-api"}`)
	repo.State = types.ScaffoldStepCompleted
	repo.Result = json.RawMessage(`{"repoName":"r","repoUrl":"https://fake.git/r.git","branch":"main"}`)
	dir := t.TempDir()

	// Unsupported pipeline provider.
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", "  createPipeline:\n    provider: gitlab-ci\n", map[string]string{"a.txt": "x"})
	if _, err := stepCreatingPipeline(context.Background(), testEnv(dir, gitprovider.NewFake(), &fakeRegistrar{}), rc, pipeline); err == nil ||
		!strings.Contains(err.Error(), "pipeline provider") {
		t.Fatalf("unsupported provider err = %v", err)
	}

	// No cluster in the tenant context.
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", testScaffoldBlock, map[string]string{"a.txt": "x"})
	noCluster := *testTenant()
	noCluster.ClusterID = ""
	bare := &RunContext{Run: rc.Run, Steps: rc.Steps, Tenant: &noCluster}
	if _, err := stepCreatingPipeline(context.Background(), testEnv(dir, gitprovider.NewFake(), &fakeRegistrar{}), bare, pipeline); err == nil ||
		!strings.Contains(err.Error(), "cluster") {
		t.Fatalf("no cluster err = %v", err)
	}
}
