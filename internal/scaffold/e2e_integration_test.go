//go:build integration

// Failure-path gap tests (M8.W5): retry after a transient git failure and
// cooperative cancel mid-run with already-created outputs retained. 404/409/
// backoff/exhaustion semantics are covered by the other integration files.
package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// failOnceGit wraps the fake provider and fails the next EnsureRepo call
// while armed — a transient git host outage.
type failOnceGit struct {
	inner  *gitprovider.Fake
	armed  bool
	failed int
}

func (g *failOnceGit) EnsureRepo(ctx context.Context, repo string) (string, error) {
	if g.armed {
		g.armed = false
		g.failed++
		return "", errors.New("git host 502: bad gateway")
	}
	return g.inner.EnsureRepo(ctx, repo)
}

func (g *failOnceGit) CommitFiles(ctx context.Context, repo, branch string, files []gitprovider.File, message string) (*gitprovider.Result, error) {
	return g.inner.CommitFiles(ctx, repo, branch, files, message)
}

func TestRetryAfterTransientGitFailure(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt.tmpl": "{{ .Values.name }}"})
	git := &failOnceGit{inner: gitprovider.NewFake(), armed: true}
	f.svc.WithExecEnv(&ExecEnv{
		Git: git, GitOrg: "acme-platform", Registrar: &fakeRegistrar{}, Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
	})

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}

	// First drive: rendering completes, creating-repo fails on the outage.
	f.svc.reconcileOnce(ctx, time.Hour)
	_, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if git.failed != 1 || steps[1].Name != "creating-repo" || steps[1].State != types.ScaffoldStepFailed || steps[1].Attempts != 1 {
		t.Fatalf("creating-repo must fail once: failed=%d step=%+v", git.failed, steps[1])
	}
	got, _, _ := f.svc.GetRun(ctx, "org:acme", run.ID)
	if got.Phase == types.ScaffoldPhaseFailed {
		t.Fatalf("non-exhausted transient failure must not settle: %+v", got)
	}

	// The outage clears; after the backoff window the retry completes the run.
	if _, err := f.db.Pool.Exec(ctx,
		`UPDATE scaffold_run_steps SET updated_at = now() - interval '1 day' WHERE run_id = $1`, run.ID); err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Minute)

	got, steps, err = f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCompleted {
		t.Fatalf("phase = %q after retry, want completed (error=%q)", got.Phase, got.Error)
	}
	// The successful retry consumes no further attempt budget (only genuine
	// failures do), so attempts stays at the one transient failure.
	if steps[1].State != types.ScaffoldStepCompleted || steps[1].Attempts != 1 {
		t.Fatalf("creating-repo retry = %+v", steps[1])
	}
	if !strings.Contains(string(got.Outputs), `"repoUrl"`) {
		t.Fatalf("outputs after retry = %s", got.Outputs)
	}
}

// cancelAfterCommitGit cancels the run right after the skeleton commit
// lands — the operator hits cancel while the run is mid-flight.
type cancelAfterCommitGit struct {
	inner  *gitprovider.Fake
	cancel func()
	done   bool
}

func (g *cancelAfterCommitGit) EnsureRepo(ctx context.Context, repo string) (string, error) {
	return g.inner.EnsureRepo(ctx, repo)
}

func (g *cancelAfterCommitGit) CommitFiles(ctx context.Context, repo, branch string, files []gitprovider.File, message string) (*gitprovider.Result, error) {
	res, err := g.inner.CommitFiles(ctx, repo, branch, files, message)
	if err == nil && !g.done {
		g.done = true
		g.cancel()
	}
	return res, err
}

func TestCancelMidRunRetainsOutputs(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt.tmpl": "{{ .Values.name }}"})
	git := &cancelAfterCommitGit{inner: gitprovider.NewFake()}
	f.svc.WithExecEnv(&ExecEnv{
		Git: git, GitOrg: "acme-platform", Registrar: &fakeRegistrar{}, Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
	})

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	git.cancel = func() {
		if err := f.svc.CancelRun(ctx, "dev-1", "org:acme", run.ID); err != nil {
			t.Errorf("cancel: %v", err)
		}
	}

	f.svc.reconcileOnce(ctx, time.Minute)

	got, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseFailed || got.Error != "cancelled" {
		t.Fatalf("cancelled mid-run = %q/%q, want failed/cancelled", got.Phase, got.Error)
	}
	// Steps up to creating-repo completed; later steps never ran.
	if steps[1].Name != "creating-repo" || steps[1].State != types.ScaffoldStepCompleted {
		t.Fatalf("creating-repo = %+v", steps[1])
	}
	if steps[2].State == types.ScaffoldStepCompleted || steps[3].State == types.ScaffoldStepCompleted {
		t.Fatalf("post-cancel steps must not complete: %+v", steps)
	}
	// The already-created repo output is retained (non-destructive cleanup).
	if !strings.Contains(string(got.Outputs), `"repoUrl"`) {
		t.Fatalf("cancelled run must retain repoUrl output: %s", got.Outputs)
	}
}
