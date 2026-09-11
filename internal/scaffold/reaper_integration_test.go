//go:build integration

// Run retention (M8.W6): terminal runs older than INARI_SCAFFOLD_RUN_TTL
// are reaped at the end of each reconcile tick; non-terminal and fresh
// terminal runs are kept.
package scaffold

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
)

func TestRunRetentionReaper(t *testing.T) {
	f := newITFixture(t)
	ctx := context.Background()
	auditStore := audit.NewStore()
	catSvc := catalog.NewService(f.db, catalog.NewStore(), nil, auditStore, nil)
	svc := NewService(f.db, NewStore(), auditStore, catSvc, Config{MaxAttempts: 5, GitOrg: "acme-platform", RunTTL: time.Hour}, slog.Default())

	mkRun := func(name string) string {
		// Distinct values per run — identical submits dedup on the
		// idempotency key.
		run, _, _, err := svc.CreateRun(ctx, "dev-1", "org:acme", "go-service", "", "",
			json.RawMessage(`{"name":"`+name+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return run.ID
	}
	setPhase := func(id, phase string, age time.Duration) {
		if _, err := f.db.Pool.Exec(ctx,
			`UPDATE scaffold_runs SET phase=$2, updated_at=now()-$3::interval WHERE id=$1`,
			id, phase, age.String()); err != nil {
			t.Fatal(err)
		}
	}
	oldCompleted := mkRun("old-completed")     // terminal, past TTL → reaped
	freshCompleted := mkRun("fresh-completed") // terminal, fresh → kept
	oldFailed := mkRun("old-failed")           // terminal, past TTL → reaped
	oldPending := mkRun("old-pending")         // non-terminal, past TTL → kept
	setPhase(oldCompleted, "completed", 2*time.Hour)
	setPhase(freshCompleted, "completed", time.Minute)
	setPhase(oldFailed, "failed", 48*time.Hour)
	setPhase(oldPending, "pending", 48*time.Hour)

	svc.reconcileOnce(ctx, time.Minute)

	exists := func(id string) bool {
		var n int
		if err := f.db.Pool.QueryRow(ctx, `SELECT count(*) FROM scaffold_runs WHERE id=$1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if exists(oldCompleted) {
		t.Error("old completed run not reaped")
	}
	if exists(oldFailed) {
		t.Error("old failed run not reaped")
	}
	if !exists(freshCompleted) {
		t.Error("fresh completed run reaped")
	}
	if !exists(oldPending) {
		t.Error("non-terminal run reaped")
	}
	// Steps cascade with the run row.
	var stepRows int
	if err := f.db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM scaffold_run_steps WHERE run_id = $1`, oldCompleted).Scan(&stepRows); err != nil {
		t.Fatal(err)
	}
	if stepRows != 0 {
		t.Errorf("orphaned steps after reap: %d", stepRows)
	}
	// TTL disabled → nothing reaped.
	svcNoTTL := NewService(f.db, NewStore(), auditStore, catSvc, Config{MaxAttempts: 5, GitOrg: "acme-platform"}, slog.Default())
	svcNoTTL.reconcileOnce(ctx, time.Minute)
	if !exists(freshCompleted) {
		t.Error("reaper ran with TTL disabled")
	}
}
