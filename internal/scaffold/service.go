// The scaffold reconcile engine (M8.W3, plan §5.1/§5.2): a goroutine that
// claims runnable runs and drives their step chains, persisting each
// settled transition with audit + outbox (EventScaffoldRunStepUpdated),
// observing cancelled_at cooperatively before every step. Persistence
// wraps the DB-free runner in runner.go (adapted from
// internal/tenantzonefactory/service.go).
package scaffold

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/types"
)

// WithExecEnv wires the backend seams the W3/W4 step engine consumes.
func (s *Service) WithExecEnv(env *ExecEnv) *Service {
	s.exec = env
	return s
}

// runLock serializes drivers for one run (reconcile ticks and, later, an
// HTTP resume) so concurrent entries can't double-execute steps.
func (s *Service) runLock(runID string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	m, ok := s.locks[runID]
	if !ok {
		m = &sync.Mutex{}
		s.locks[runID] = m
	}
	return m
}

// phaseForStep maps a step to the run phase shown while it runs — phases
// are 1:1 with steps (plan §3).
func phaseForStep(name string) types.ScaffoldPhase { return types.ScaffoldPhase(name) }

// RunReconcileLoop claims and drives runnable runs on an interval — the
// crash-recovery, async-poll and cancel-settlement engine (§5.2). Runs
// until ctx is cancelled.
func (s *Service) RunReconcileLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		s.reconcileOnce(ctx, interval)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// reconcileOnce drives every claimable run once: runnable runs first, then
// cancelled-but-unsettled runs (idle cancels that must still settle to
// failed). backoffBase doubles as the backoff unit for failed steps. A run
// parked in waiting (or skipped by backoff) remains claimable, so the
// drain loop stops when the claim repeats a run already driven this tick.
func (s *Service) reconcileOnce(ctx context.Context, backoffBase time.Duration) {
	seen := map[string]bool{}
	for {
		run, err := s.claimNext(ctx, backoffBase)
		if err != nil {
			s.log.Warn("scaffold: reconcile claim failed", "error", err)
			break
		}
		if run == nil || seen[run.ID] {
			break
		}
		seen[run.ID] = true
		if err := s.driveRun(ctx, run); err != nil && ctx.Err() == nil {
			s.log.Warn("scaffold: drive run failed", "run", run.ID, "error", err)
		}
	}
	s.reapExpired(ctx)
}

// reapExpired deletes terminal runs older than the configured TTL (M8.W6
// retention). Best-effort: a reaper failure never blocks the drive loop.
func (s *Service) reapExpired(ctx context.Context) {
	if s.cfg.RunTTL <= 0 {
		return
	}
	n, err := s.store.DeleteTerminalRuns(ctx, s.db.Pool, time.Now().Add(-s.cfg.RunTTL))
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("scaffold: run reaper failed", "error", err)
		}
		return
	}
	if n > 0 {
		s.log.Info("scaffold: reaped expired runs", "count", n)
	}
}

// claimNext picks the next run to drive inside a short TX (SKIP LOCKED):
// first a runnable run, else a cancelled-but-unsettled one.
func (s *Service) claimNext(ctx context.Context, backoffBase time.Duration) (*types.ScaffoldRun, error) {
	var run *types.ScaffoldRun
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		r, err := s.store.ClaimNextRunnable(ctx, tx, backoffBase)
		if err != nil || r != nil {
			run = r
			return err
		}
		r, err = s.store.ClaimNextCancelled(ctx, tx)
		run = r
		return err
	})
	return run, err
}

// driveRun executes one run's remaining steps, persisting each settled
// transition in a TX with audit + outbox, and settles the run on
// completion, exhaustion or cancel.
func (s *Service) driveRun(ctx context.Context, run *types.ScaffoldRun) error {
	lock := s.runLock(run.ID)
	lock.Lock()
	defer lock.Unlock()
	// Re-read under the lock: fresh phase + cancelled_at.
	fresh, err := s.store.GetRun(ctx, s.db.Pool, run.OrgID, run.ID)
	if err != nil {
		return err
	}
	run = fresh
	if run.Phase == types.ScaffoldPhaseCompleted || run.Phase == types.ScaffoldPhaseFailed {
		return nil
	}
	steps, err := s.store.ListSteps(ctx, s.db.Pool, run.ID)
	if err != nil {
		return err
	}
	stepMap := make(map[string]*types.ScaffoldRunStep, len(steps))
	for i := range steps {
		st := steps[i]
		stepMap[st.Name] = &st
	}
	var tenant *TenantContext
	if s.exec != nil && s.exec.Tenants != nil {
		tenant, err = s.exec.Tenants.ResolveTenant(ctx, run.OrgID)
		if err != nil {
			return fmt.Errorf("scaffold: resolve tenant: %w", err)
		}
	}
	actor := "system:scaffold"
	rc := &RunContext{Run: run, Steps: stepMap, Tenant: tenant, Actor: actor}
	isCancelled := func() bool {
		r, err := s.store.GetRun(ctx, s.db.Pool, run.OrgID, run.ID)
		return err == nil && r.CancelledAt != nil
	}
	onUpdate := func(ctx context.Context, rc *RunContext, st *types.ScaffoldRunStep) error {
		if st.State == types.ScaffoldStepRunning {
			return nil // only persist settled transitions
		}
		run.Phase = phaseForStep(st.Name)
		run.Error = ""
		if st.State == types.ScaffoldStepFailed {
			run.Error = st.Error
		}
		return s.db.WithTx(ctx, func(tx pgx.Tx) error {
			if err := s.store.UpdateStep(ctx, tx, st); err != nil {
				return err
			}
			if err := s.store.UpdateRunPhase(ctx, tx, run.ID, run.Phase, run.Error, run.Outputs); err != nil {
				return err
			}
			if err := s.audit.Record(ctx, tx, &types.AuditEvent{
				OrgID: run.OrgID, Actor: actor, Action: "scaffold.step_updated",
				ObjectType: "scaffold_run", ObjectID: run.ID,
				Payload: json.RawMessage(fmt.Sprintf(`{"step":%q,"state":%q,"attempts":%d}`, st.Name, st.State, st.Attempts)),
			}); err != nil {
				return err
			}
			return audit.AppendOutbox(ctx, tx, run.OrgID, types.EventScaffoldRunStepUpdated, types.ScaffoldRunPayload{
				OrgID: run.OrgID, RunID: run.ID, Version: run.TemplateVersion,
				Phase: string(run.Phase), Step: st.Name, StepStatus: st.State,
			})
		})
	}
	// Two passes (W6): rendering first, then the approval hold, then the
	// remaining phases — the gate sits between rendering and the external
	// side effects (repo/pipeline/catalog/rbac), never mid-phase.
	var complete bool
	var runErr error
	if st := stepMap["rendering"]; st == nil || st.State != types.ScaffoldStepCompleted {
		_, runErr = RunSteps(ctx, s.execEnv(), rc, stepNames[:1], stepFuncs, onUpdate, isCancelled)
	}
	gated := false
	if runErr == nil && !isCancelled() {
		var err error
		gated, err = s.maybeGate(ctx, run, stepMap)
		if err != nil {
			return err
		}
	}
	if runErr == nil && !gated {
		complete, runErr = RunSteps(ctx, s.execEnv(), rc, stepNames[1:], stepFuncs, onUpdate, isCancelled)
	}
	switch {
	case errors.Is(runErr, ErrCancelled):
		return s.finalize(ctx, run, types.ScaffoldPhaseFailed, "cancelled", types.EventScaffoldRunFailed, actor)
	case runErr != nil:
		if st := failedStep(stepMap, stepNames); st != nil && st.Attempts > maxAttemptsOf(st, s.cfg.MaxAttempts) {
			return s.finalize(ctx, run, types.ScaffoldPhaseFailed,
				fmt.Sprintf("manual_intervention: step %s exhausted %d attempts: %s", st.Name, st.MaxAttempts, st.Error),
				types.EventScaffoldRunFailed, actor)
		}
		return nil // retry after backoff on the next reconcile tick
	case complete:
		return s.finalize(ctx, run, types.ScaffoldPhaseCompleted, "", types.EventScaffoldRunCompleted, actor)
	default:
		return nil // waiting on an async operation (or a W4 placeholder); the loop re-enters
	}
}

// approvalHoldKey is the run-outputs key holding the approval request ID
// of a gated run. Set when the run parks in pending_approval; kept after
// resume so a re-driven run never requests a second approval (the retry
// route clears it to re-gate).
const approvalHoldKey = "approvalId"

// maybeGate parks the run in pending_approval when its template declares
// scaffold.requiresApproval and the run has finished rendering but not yet
// started the remaining phases. Returns gated=true when the run was parked
// (the caller must not drive it further this tick). Ungated templates, an
// unfinished rendering step, an already-gated run, or missing seams are
// pass-throughs.
func (s *Service) maybeGate(ctx context.Context, run *types.ScaffoldRun, steps map[string]*types.ScaffoldRunStep) (bool, error) {
	r := steps["rendering"]
	if r == nil || r.State != types.ScaffoldStepCompleted {
		return false, nil
	}
	if outputValue(run.Outputs, approvalHoldKey) != "" {
		return false, nil
	}
	env := s.execEnv()
	if env.Gate == nil || env.Templates == nil {
		return false, nil
	}
	name := strings.TrimPrefix(run.TemplateItemID, "template:")
	pkg, err := env.Templates.Get(ctx, name, run.TemplateVersion)
	if err != nil {
		return false, err
	}
	if !pkg.Manifest.Scaffold.requiresApproval() {
		return false, nil
	}
	item, err := s.catalog.GetItemByID(ctx, run.TemplateItemID)
	if err != nil {
		return false, fmt.Errorf("scaffold: gate: load template item %s: %w", run.TemplateItemID, err)
	}
	spec, err := json.Marshal(map[string]string{"runId": run.ID})
	if err != nil {
		return false, err
	}
	res, err := env.Gate.Gate(ctx, approvals.GateInput{
		OrgID: run.OrgID, Item: item, Version: run.TemplateVersion,
		Requester: run.CreatedBy, Spec: spec,
	})
	if err != nil {
		return false, fmt.Errorf("scaffold: gate run %s: %w", run.ID, err)
	}
	if res.Approved {
		return false, nil
	}
	outputs, err := setOutput(run.Outputs, approvalHoldKey, res.ApprovalID)
	if err != nil {
		return false, err
	}
	run.Outputs = outputs
	actor := "system:scaffold"
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpdateRunPhase(ctx, tx, run.ID, types.ScaffoldPhasePendingApproval, "", outputs); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: run.OrgID, Actor: actor, Action: "scaffold.approval_requested",
			ObjectType: "scaffold_run", ObjectID: run.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"approvalId":%q}`, res.ApprovalID)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, run.OrgID, types.EventScaffoldRunStepUpdated, types.ScaffoldRunPayload{
			OrgID: run.OrgID, RunID: run.ID, Version: run.TemplateVersion,
			Phase: string(types.ScaffoldPhasePendingApproval),
		})
	})
	if err != nil {
		return false, err
	}
	run.Phase = types.ScaffoldPhasePendingApproval
	return true, nil
}

// setOutput returns a copy of the run outputs JSON object with key set.
func setOutput(raw json.RawMessage, key string, value any) (json.RawMessage, error) {
	var outputs map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &outputs)
	}
	if outputs == nil {
		outputs = map[string]any{}
	}
	outputs[key] = value
	return json.Marshal(outputs)
}

// deleteOutput returns a copy of the run outputs JSON object with key removed.
func deleteOutput(raw json.RawMessage, key string) (json.RawMessage, error) {
	var outputs map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &outputs)
	}
	delete(outputs, key)
	return json.Marshal(outputs)
}

// outputString reads one string key from the run outputs JSON object.
func outputValue(raw json.RawMessage, key string) string {
	var outputs map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &outputs) != nil {
		return ""
	}
	s, _ := outputs[key].(string)
	return s
}

// nextPhaseForRun computes the phase a resumed run re-enters: the first
// non-completed step in execution order (fallback: creating-repo — the
// gate sits between rendering and the remaining phases).
func nextPhaseForRun(steps []types.ScaffoldRunStep) types.ScaffoldPhase {
	for _, st := range steps {
		if st.State != types.ScaffoldStepCompleted {
			return phaseForStep(st.Name)
		}
	}
	return types.ScaffoldPhaseCreatingRepo
}

// execEnv tolerates a nil exec env (steps then fail on the missing seam)
// and backfills GitOrg from the service config.
func (s *Service) execEnv() *ExecEnv {
	env := s.exec
	if env == nil {
		env = &ExecEnv{}
	}
	if env.GitOrg == "" {
		env.GitOrg = s.cfg.GitOrg
	}
	return env
}

// failedStep returns the first failed step in execution order, if any.
func failedStep(steps map[string]*types.ScaffoldRunStep, order []string) *types.ScaffoldRunStep {
	for _, name := range order {
		if st := steps[name]; st != nil && st.State == types.ScaffoldStepFailed {
			return st
		}
	}
	return nil
}

func maxAttemptsOf(st *types.ScaffoldRunStep, fallback int) int {
	if st.MaxAttempts > 0 {
		return st.MaxAttempts
	}
	return fallback
}

// finalize writes the terminal run phase with the archived audit event and
// outbox notification (settle pattern from the tenant zone factory).
func (s *Service) finalize(ctx context.Context, run *types.ScaffoldRun, phase types.ScaffoldPhase, errMsg, event, actor string) error {
	run.Phase = phase
	run.Error = errMsg
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpdateRunPhase(ctx, tx, run.ID, phase, errMsg, run.Outputs); err != nil {
			return err
		}
		ev := &types.AuditEvent{
			OrgID: run.OrgID, Actor: actor, Action: event,
			ObjectType: "scaffold_run", ObjectID: run.ID,
		}
		if errMsg != "" {
			ev.Payload = json.RawMessage(fmt.Sprintf(`{"error":%q}`, errMsg))
		}
		if err := s.audit.Record(ctx, tx, ev); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, run.OrgID, event, types.ScaffoldRunPayload{
			OrgID: run.OrgID, RunID: run.ID, Version: run.TemplateVersion, Phase: string(phase),
		})
	})
}
