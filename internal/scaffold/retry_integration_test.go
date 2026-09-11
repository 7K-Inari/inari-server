//go:build integration

// Retry route (M8.W6, parent plan §5.3): POST
// /api/v1/tenants/{org}/scaffold-runs/{runId}/retry resets a failed run to
// its first non-completed step so the reconcile loop resumes it —
// non-destructive recovery from manual_intervention instead of a new run.
package scaffold

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// failGit always fails EnsureRepo — creating-repo never succeeds.
type failGit struct{ inner *gitprovider.Fake }

func (g failGit) EnsureRepo(context.Context, string) (string, error) {
	return "", errGitDown
}

func (g failGit) CommitFiles(ctx context.Context, repo, branch string, files []gitprovider.File, message string) (*gitprovider.Result, error) {
	return g.inner.CommitFiles(ctx, repo, branch, files, message)
}

var errGitDown = errorString("git host 502: bad gateway")

type errorString string

func (e errorString) Error() string { return string(e) }

// driveToFailed runs a run into the terminal failed phase by exhausting
// the creating-repo attempt budget.
func driveToFailed(t *testing.T, f *itFixture, runID string) {
	t.Helper()
	ctx := context.Background()
	f.svc.reconcileOnce(ctx, time.Hour) // rendering ok, creating-repo fails once
	if _, err := f.db.Pool.Exec(ctx,
		`UPDATE scaffold_run_steps SET attempts = max_attempts, updated_at = now() - interval '1 day'
		 WHERE run_id = $1 AND state = 'failed'`, runID); err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Minute) // budget exhausted → failed
	got, _, err := f.svc.GetRun(ctx, "org:acme", runID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseFailed {
		t.Fatalf("phase = %q, want failed (manual_intervention)", got.Phase)
	}
}

func TestRetryFailedRun(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt.tmpl": "{{ .Values.name }}"})
	git := gitprovider.NewFake()
	failing := failGit{inner: git}
	f.svc.WithExecEnv(&ExecEnv{
		Git: failing, GitOrg: "acme-platform", Registrar: &fakeRegistrar{},
		Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
	})

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	driveToFailed(t, f, run.ID)

	// The git outage clears; the operator retries via the canonical API.
	f.svc.WithExecEnv(&ExecEnv{
		Git: git, GitOrg: "acme-platform", Registrar: &fakeRegistrar{},
		Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
	})
	code, body := f.req(t, "POST", "/api/v1/tenants/acme/scaffold-runs/"+run.ID+"/retry", "good", "")
	if code != 200 {
		t.Fatalf("retry = %d: %s", code, body)
	}
	got, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCreatingRepo {
		t.Fatalf("phase after retry = %q, want creating-repo (first non-completed step)", got.Phase)
	}
	if got.Error != "" {
		t.Fatalf("error after retry = %q, want cleared", got.Error)
	}
	if steps[0].State != types.ScaffoldStepCompleted {
		t.Fatalf("rendering must stay completed: %+v", steps[0])
	}
	for _, st := range steps[1:] {
		if st.State != types.ScaffoldStepPending || st.Attempts != 0 || st.Error != "" {
			t.Fatalf("step %s not reset: %+v", st.Name, st)
		}
	}
	// Outbox carries the retry event for observers (notifications, audit).
	var n int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE event_type = 'scaffold.run_retried' AND org_id = 'org:acme'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("scaffold.run_retried outbox events = %d, want 1", n)
	}

	// The reconcile loop resumes from creating-repo and completes.
	f.svc.reconcileOnce(ctx, time.Minute)
	got, _, err = f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseCompleted {
		t.Fatalf("phase after retried drive = %q (error=%q), want completed", got.Phase, got.Error)
	}
	if !strings.Contains(string(got.Outputs), `"repoUrl"`) {
		t.Fatalf("outputs after retried drive = %s", got.Outputs)
	}
}

func TestRetryRejectsNonFailedRun(t *testing.T) {
	f := newITFixture(t)
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt.tmpl": "{{ .Values.name }}"})
	f.svc.WithExecEnv(&ExecEnv{
		Git: gitprovider.NewFake(), GitOrg: "acme-platform", Registrar: &fakeRegistrar{},
		Upsert: &fakeUpserter{}, RBAC: &fakeRBACBinder{},
		Templates: &FilePuller{Root: dir}, Tenants: itResolver(),
	})
	run, _, _, err := f.svc.CreateRun(context.Background(), "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	// Pending (not yet driven) → 409.
	if code, body := f.req(t, "POST", "/api/v1/tenants/acme/scaffold-runs/"+run.ID+"/retry", "good", ""); code != 409 {
		t.Fatalf("retry of pending run = %d, want 409: %s", code, body)
	}
	// Cross-org → 404.
	if code, _ := f.req(t, "POST", "/api/v1/tenants/other/scaffold-runs/"+run.ID+"/retry", "other", ""); code != 404 {
		t.Fatalf("cross-org retry = %d, want 404", code)
	}
	// Unknown run → 404.
	if code, _ := f.req(t, "POST", "/api/v1/tenants/acme/scaffold-runs/run:nope/retry", "good", ""); code != 404 {
		t.Fatalf("unknown run retry = %d, want 404", code)
	}
}
