//go:build integration

package scaffold

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

type itTenantResolver map[string]*TenantContext

func (r itTenantResolver) ResolveTenant(_ context.Context, orgID string) (*TenantContext, error) {
	if tc, ok := r[orgID]; ok {
		return tc, nil
	}
	return nil, fmt.Errorf("unknown org %s", orgID)
}

func itResolver() itTenantResolver {
	return itTenantResolver{
		"org:acme":  {Slug: "acme", OrgID: "org:acme", Namespace: "acme", GroupPath: "tenant-acme/members"},
		"org:other": {Slug: "other", OrgID: "org:other", Namespace: "other", GroupPath: "tenant-other/members"},
	}
}

func TestReconcileDrivesRendering(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{
		"deploy/app.yaml.tmpl": "name: {{ .Values.name }}\nns: {{ .Tenant.Namespace }}\nrun: {{ .Run.ID }}\n",
	})
	f.svc.WithExecEnv(&ExecEnv{Templates: &FilePuller{Root: dir}, Tenants: itResolver()})

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}

	f.svc.reconcileOnce(ctx, time.Minute)

	got, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Rendering completed; the run parks at the W4 placeholder.
	if got.Phase != types.ScaffoldPhaseCreatingRepo {
		t.Fatalf("phase = %q, want creating-repo", got.Phase)
	}
	if steps[0].Name != "rendering" || steps[0].State != types.ScaffoldStepCompleted {
		t.Fatalf("rendering step = %+v", steps[0])
	}
	var res renderResult
	if err := json.Unmarshal(steps[0].Result, &res); err != nil || len(res.Files) != 1 {
		t.Fatalf("render result = %s (%v)", steps[0].Result, err)
	}
	if res.Files[0].Path != "deploy/app.yaml" ||
		!strings.Contains(res.Files[0].Content, "name: payments-api") ||
		!strings.Contains(res.Files[0].Content, "ns: acme") ||
		!strings.Contains(res.Files[0].Content, "run: "+run.ID) {
		t.Fatalf("rendered content wrong: %+v", res.Files[0])
	}
	if steps[1].Name != "creating-repo" || steps[1].State != types.ScaffoldStepWaiting || steps[1].Attempts != 0 {
		t.Fatalf("placeholder step = %+v", steps[1])
	}
	var outputs map[string]any
	if err := json.Unmarshal(got.Outputs, &outputs); err != nil || outputs["renderedFiles"] != float64(1) {
		t.Fatalf("outputs = %s (%v)", got.Outputs, err)
	}

	// Step transitions produced outbox events + audit rows.
	var events int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE event_type=$1 AND payload->>'runId'=$2`,
		types.EventScaffoldRunStepUpdated, run.ID).Scan(&events); err != nil || events < 2 {
		t.Fatalf("want >=2 step_updated outbox events, got %d (%v)", events, err)
	}
	var audits int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action='scaffold.step_updated' AND object_id=$1`,
		run.ID).Scan(&audits); err != nil || audits < 2 {
		t.Fatalf("want >=2 step_updated audit rows, got %d (%v)", audits, err)
	}

	// Idempotent re-drive: nothing changes.
	f.svc.reconcileOnce(ctx, time.Minute)
	again, againSteps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Phase != got.Phase || againSteps[0].State != types.ScaffoldStepCompleted {
		t.Fatalf("re-drive mutated state: %+v", againSteps[0])
	}
}

func TestReconcileSettlesCancelledIdleRun(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeFixtureTemplate(t, dir, "go-service", "1.0.0", map[string]string{"a.txt": "x"})
	f.svc.WithExecEnv(&ExecEnv{Templates: &FilePuller{Root: dir}, Tenants: itResolver()})

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CancelRun(ctx, "dev-1", "org:acme", run.ID); err != nil {
		t.Fatal(err)
	}

	f.svc.reconcileOnce(ctx, time.Minute)

	got, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseFailed || got.Error != "cancelled" {
		t.Fatalf("cancelled run = %q/%q, want failed/cancelled", got.Phase, got.Error)
	}
	if steps[0].State != types.ScaffoldStepFailed || steps[0].Error != "cancelled" {
		t.Fatalf("cancelled step = %+v", steps[0])
	}
	var failed int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbox WHERE event_type=$1 AND payload->>'runId'=$2`,
		types.EventScaffoldRunFailed, run.ID).Scan(&failed); err != nil || failed != 1 {
		t.Fatalf("want 1 scaffold.failed outbox event, got %d (%v)", failed, err)
	}
	// Settled runs are never claimed again.
	f.svc.reconcileOnce(ctx, time.Minute)
	again, _, _ := f.svc.GetRun(ctx, "org:acme", run.ID)
	if again.Phase != types.ScaffoldPhaseFailed {
		t.Fatalf("settled run re-driven: %q", again.Phase)
	}
}

func TestReconcileBackoffSkipsRecentlyFailed(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	// No template on disk: the rendering step fails every drive.
	f.svc.WithExecEnv(&ExecEnv{Templates: &FilePuller{Root: t.TempDir()}, Tenants: itResolver()})

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}

	f.svc.reconcileOnce(ctx, time.Hour)
	_, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].State != types.ScaffoldStepFailed || steps[0].Attempts != 1 {
		t.Fatalf("first drive must fail the rendering step: %+v", steps[0])
	}

	// Inside the backoff window the run is not re-claimed.
	f.svc.reconcileOnce(ctx, time.Hour)
	_, steps, _ = f.svc.GetRun(ctx, "org:acme", run.ID)
	if steps[0].Attempts != 1 {
		t.Fatalf("backoff window ignored: attempts = %d", steps[0].Attempts)
	}

	// Once the window elapses the run is re-driven and consumes another
	// attempt.
	if _, err := f.db.Pool.Exec(ctx,
		`UPDATE scaffold_run_steps SET updated_at = now() - interval '3 hours'
		 WHERE run_id = $1 AND name = 'rendering'`, run.ID); err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Hour) // window: 1h * 2^0 for attempt 1
	_, steps, _ = f.svc.GetRun(ctx, "org:acme", run.ID)
	if steps[0].Attempts != 2 {
		t.Fatalf("retry after backoff did not happen: attempts = %d", steps[0].Attempts)
	}
	// Non-exhausted failure is not terminal.
	got, _, _ := f.svc.GetRun(ctx, "org:acme", run.ID)
	if got.Phase == types.ScaffoldPhaseFailed {
		t.Fatalf("non-exhausted failure must not settle: %+v", got)
	}
}

func TestReconcileExhaustionSettlesManualIntervention(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	f.svc.WithExecEnv(&ExecEnv{Templates: &FilePuller{Root: t.TempDir()}, Tenants: itResolver()})

	run, _, _, err := f.svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "", json.RawMessage(`{"name":"payments-api"}`))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a step already at its budget: next failure exceeds it. The
	// timestamp must sit outside the backoff window (60s * 2^(attempts-1))
	// or the run is not claimable yet.
	if _, err := f.db.Pool.Exec(ctx,
		`UPDATE scaffold_run_steps SET attempts = max_attempts, state = 'failed',
		   updated_at = now() - interval '1 day'
		 WHERE run_id = $1 AND name = 'rendering'`, run.ID); err != nil {
		t.Fatal(err)
	}

	f.svc.reconcileOnce(ctx, time.Minute)

	got, steps, err := f.svc.GetRun(ctx, "org:acme", run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != types.ScaffoldPhaseFailed {
		t.Fatalf("exhausted run phase = %q, want failed", got.Phase)
	}
	if got.Error == "" || !strings.HasPrefix(got.Error, "manual_intervention:") {
		t.Fatalf("exhausted run error = %q", got.Error)
	}
	if steps[0].Attempts != steps[0].MaxAttempts+1 {
		t.Fatalf("attempts = %d, want max+1", steps[0].Attempts)
	}
	// Terminal runs are never claimed again even after the window.
	if _, err := f.db.Pool.Exec(ctx,
		`UPDATE scaffold_run_steps SET updated_at = now() - interval '30 days' WHERE run_id = $1`, run.ID); err != nil {
		t.Fatal(err)
	}
	f.svc.reconcileOnce(ctx, time.Minute)
	again, _, _ := f.svc.GetRun(ctx, "org:acme", run.ID)
	if again.Phase != types.ScaffoldPhaseFailed || again.Error != got.Error {
		t.Fatalf("terminal run re-driven: %+v", again)
	}
}
