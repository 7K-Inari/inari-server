// Per-tenant git org override + pipeline-kind plumbing (M8.W6, parent
// plan §8): the creating-repo step resolves the tenant's TenantGitConfig
// (scaffold_git_org beats the global GitOrg; the manifest's defaultBranch
// beats the tenant's baseBranch), and pipeline providers resolve through
// a kind registry (github-actions remains the only implemented kind).
package scaffold

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakeGitConfigs resolves fixed per-tenant git configs.
type fakeGitConfigs map[string]*types.TenantGitConfig

func (f fakeGitConfigs) GitConfigForOrg(_ context.Context, orgID string) (*types.TenantGitConfig, error) {
	return f[orgID], nil
}

func TestCreatingRepoTenantGitOrgOverride(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", testScaffoldBlock, map[string]string{"a.txt": "x"})
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}
	env := testEnv(dir, git, nil)
	env.GitConfigs = fakeGitConfigs{
		"org:acme": {OrgID: "org:acme", Repo: "acme/inari-state", BaseBranch: "develop", ScaffoldGitOrg: "acme-apps"},
	}

	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil {
		t.Fatal(err)
	}
	// The tenant override wins over the global GitOrg.
	if res.RepoName != "acme-apps/acme-payments-api" {
		t.Fatalf("repoName = %q, want tenant override acme-apps/...", res.RepoName)
	}
	// The manifest's defaultBranch (main) beats the tenant's baseBranch.
	if res.Branch != "main" {
		t.Fatalf("branch = %q, want main (manifest wins)", res.Branch)
	}
}

func TestCreatingRepoTenantBaseBranchFallback(t *testing.T) {
	dir := t.TempDir()
	// Manifest without createRepo.defaultBranch: the tenant's baseBranch
	// becomes the skeleton commit branch.
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", "  createRepo:\n    visibility: private\n", map[string]string{"a.txt": "x"})
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}
	env := testEnv(dir, git, nil)
	env.GitConfigs = fakeGitConfigs{
		"org:acme": {OrgID: "org:acme", Repo: "acme/inari-state", BaseBranch: "develop"},
	}

	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Branch != "develop" {
		t.Fatalf("branch = %q, want develop (tenant baseBranch fallback)", res.Branch)
	}
	// No override → the global GitOrg applies.
	if res.RepoName != "inari-apps/acme-payments-api" {
		t.Fatalf("repoName = %q, want global inari-apps/...", res.RepoName)
	}
}

func TestCreatingRepoNilTenantConfigFallsBack(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0", testScaffoldBlock, map[string]string{"a.txt": "x"})
	rc, repo, _ := stepsFixture(t, `{"name":"payments-api"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}
	env := testEnv(dir, git, nil)
	env.GitConfigs = fakeGitConfigs{} // no row for the org

	done, err := stepCreatingRepo(context.Background(), env, rc, repo)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	var res createRepoResult
	if err := json.Unmarshal(repo.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.RepoName != "inari-apps/acme-payments-api" || res.Branch != "main" {
		t.Fatalf("result = %+v, want global org + manifest branch", res)
	}
}

func TestCreatingPipelineUnknownKind(t *testing.T) {
	dir := t.TempDir()
	writeScaffoldTemplate(t, dir, "go-service", "1.0.0",
		"  createPipeline:\n    provider: gitlab-ci\n", map[string]string{"a.txt": "x"})
	rc, repo, pipeline := stepsFixture(t, `{"name":"payments-api"}`)
	repo.Result = json.RawMessage(`{"repoName":"inari-apps/acme-payments-api","repoUrl":"https://fake.git/x.git","branch":"main","commitSha":"abc"}`)
	git := &countingGit{Fake: gitprovider.NewFake()}

	_, err := stepCreatingPipeline(context.Background(), testEnv(dir, git, &fakeRegistrar{}), rc, pipeline)
	if err == nil {
		t.Fatal("unknown pipeline kind must fail the step")
	}
}

func TestPipelineKindRegistry(t *testing.T) {
	if _, ok := pipelineKinds["github-actions"]; !ok {
		t.Fatal("github-actions kind not registered")
	}
	got := pipelineKinds["github-actions"].PipelineURL("https://github.com/acme/app.git")
	if got != "https://github.com/acme/app/actions" {
		t.Fatalf("PipelineURL = %q", got)
	}
}
