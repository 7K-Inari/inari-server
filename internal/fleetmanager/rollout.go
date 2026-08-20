// Staged fleet rollouts (plan §5.11): stages select ClusterSets, fan out
// desired-state commands via the agent queue (credential-free), gate on
// agent-reported health, and optionally pause on timed/approval gates
// before and after each stage. Supports stop/resume and
// rollback-to-previous-version.
package fleetmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/approvals"
	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// GateRequester creates lifecycle approvals for stage gates
// (approvals.Service seam).
type GateRequester interface {
	RequestLifecycleApproval(ctx context.Context, in approvals.LifecycleApprovalInput) (*types.ApprovalRequest, error)
}

// rolloutTransitions is the explicit rollout state machine.
var rolloutTransitions = map[string][]string{
	types.RolloutStatePending:     {types.RolloutStateRunning, types.RolloutStateFailed},
	types.RolloutStateRunning:     {types.RolloutStateWaitingGate, types.RolloutStatePaused, types.RolloutStateFailed, types.RolloutStateCompleted, types.RolloutStateRolledBack},
	types.RolloutStateWaitingGate: {types.RolloutStateRunning, types.RolloutStatePaused, types.RolloutStateFailed, types.RolloutStateRolledBack},
	types.RolloutStatePaused:      {types.RolloutStateRunning, types.RolloutStateWaitingGate, types.RolloutStateFailed, types.RolloutStateRolledBack},
	types.RolloutStateFailed:      {types.RolloutStateRolledBack, types.RolloutStateRunning},
	types.RolloutStateCompleted:   {types.RolloutStateRolledBack},
}

// CanRolloutTransition reports whether from→to is a legal rollout transition.
func CanRolloutTransition(from, to string) bool {
	for _, s := range rolloutTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// ParseMaxConcurrency resolves a stage's maxConcurrency spec (count like
// "3" or percentage like "25%") against the stage member count. The result
// is always at least 1 and at most total.
func ParseMaxConcurrency(spec string, total int) (int, error) {
	if total <= 0 {
		return 0, nil
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, fmt.Errorf("%w: maxConcurrency is required", ErrInvalidInput)
	}
	if strings.HasSuffix(spec, "%") {
		pct, err := strconv.Atoi(strings.TrimSuffix(spec, "%"))
		if err != nil || pct <= 0 || pct > 100 {
			return 0, fmt.Errorf("%w: maxConcurrency percent must be 1-100", ErrInvalidInput)
		}
		n := (total*pct + 99) / 100 // ceil
		if n < 1 {
			n = 1
		}
		return n, nil
	}
	n, err := strconv.Atoi(spec)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%w: maxConcurrency must be a positive count or percentage", ErrInvalidInput)
	}
	if n > total {
		n = total
	}
	return n, nil
}

// ValidRolloutKind reports whether kind is a supported rollout kind.
func ValidRolloutKind(kind string) bool {
	switch kind {
	case types.RolloutKindCapability, types.RolloutKindPolicyPack,
		types.RolloutKindAgentUpgrade, types.RolloutKindCatalogVersion:
		return true
	}
	return false
}

// CreateRolloutInput is one rollout definition.
type CreateRolloutInput struct {
	Name           string
	Kind           string
	TargetRef      string
	DesiredVersion string
	Stages         []types.RolloutStage
}

func validateStages(stages []types.RolloutStage) error {
	if len(stages) == 0 {
		return fmt.Errorf("%w: at least one stage is required", ErrInvalidInput)
	}
	for i, st := range stages {
		if len(st.ClusterSetIDs) == 0 {
			return fmt.Errorf("%w: stage %d selects no cluster sets", ErrInvalidInput, i)
		}
		if _, err := ParseMaxConcurrency(st.MaxConcurrency, 100); err != nil {
			return fmt.Errorf("stage %d: %w", i, err)
		}
		for _, g := range []*types.RolloutStageGate{st.BeforeGate, st.AfterGate} {
			if g == nil {
				continue
			}
			switch g.Type {
			case "wait":
				if g.WaitSeconds <= 0 {
					return fmt.Errorf("%w: stage %d wait gate requires waitSeconds > 0", ErrInvalidInput, i)
				}
			case "approval":
			default:
				return fmt.Errorf("%w: stage %d gate type must be wait|approval", ErrInvalidInput, i)
			}
		}
	}
	return nil
}

// CreateRollout validates and persists a rollout in pending state.
func (s *Service) CreateRollout(ctx context.Context, actor, orgID string, in CreateRolloutInput) (*types.Rollout, error) {
	if in.Name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if !ValidRolloutKind(in.Kind) {
		return nil, fmt.Errorf("%w: kind must be capability|policy_pack|agent_upgrade|catalog_version", ErrInvalidInput)
	}
	if err := validateStages(in.Stages); err != nil {
		return nil, err
	}
	for _, st := range in.Stages {
		for _, g := range []*types.RolloutStageGate{st.BeforeGate, st.AfterGate} {
			if g != nil && g.Type == "approval" && s.gates == nil {
				return nil, fmt.Errorf("fleetmanager: approval gate configured but no gate requester wired")
			}
		}
	}
	for _, st := range in.Stages {
		for _, setID := range st.ClusterSetIDs {
			if _, err := s.GetClusterSet(ctx, orgID, setID); err != nil {
				return nil, fmt.Errorf("stage cluster set %s: %w", setID, err)
			}
		}
	}
	r := &types.Rollout{
		ID: "rollout:" + newUUID(), OrgID: orgID, Name: in.Name, Kind: in.Kind,
		TargetRef: in.TargetRef, DesiredVersion: in.DesiredVersion, Stages: in.Stages,
		CreatedBy: actor,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.createRollout(ctx, tx, r); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "rollout.created", ObjectType: "rollout", ObjectID: r.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventRolloutCreated, types.RolloutPayload{
			OrgID: orgID, RolloutID: r.ID,
		})
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// GetRollout returns one rollout scoped to the org.
func (s *Service) GetRollout(ctx context.Context, orgID, id string) (*types.Rollout, error) {
	r, err := s.store.getRollout(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if r.OrgID != orgID {
		return nil, ErrNotFound
	}
	return r, nil
}

// ListRollouts returns the org's rollouts, newest first.
func (s *Service) ListRollouts(ctx context.Context, orgID string) ([]types.Rollout, error) {
	return s.store.listRollouts(ctx, s.db.Pool, orgID)
}

// RolloutTargets returns the per-cluster target state of one stage.
func (s *Service) RolloutTargets(ctx context.Context, orgID, id string, stage int) ([]types.RolloutTarget, error) {
	if _, err := s.GetRollout(ctx, orgID, id); err != nil {
		return nil, err
	}
	return s.store.listTargets(ctx, s.db.Pool, id, stage)
}

// transition CAS-moves the rollout state, recording audit + outbox.
func (s *Service) transition(ctx context.Context, q db.Querier, r *types.Rollout, to string, stage int, gateCtx *types.RolloutGateContext, actor string) error {
	if !CanRolloutTransition(r.State, to) {
		return fmt.Errorf("%w: %s → %s", ErrInvalidTransition, r.State, to)
	}
	ok, err := s.store.setRolloutState(ctx, q, r.ID, r.State, to, stage, gateCtx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: rollout %s moved concurrently", ErrInvalidTransition, r.ID)
	}
	event := map[string]string{
		types.RolloutStateRunning:     types.EventRolloutStarted,
		types.RolloutStatePaused:      types.EventRolloutPaused,
		types.RolloutStateCompleted:   types.EventRolloutCompleted,
		types.RolloutStateFailed:      types.EventRolloutFailed,
		types.RolloutStateRolledBack:  types.EventRolloutRolledBack,
		types.RolloutStateWaitingGate: types.EventRolloutGateEntered,
	}[to]
	if event == "" {
		event = types.EventRolloutResumed
	}
	if err := s.audit.Record(ctx, q, &types.AuditEvent{
		OrgID: r.OrgID, Actor: actor, Action: "rollout." + to, ObjectType: "rollout", ObjectID: r.ID,
	}); err != nil {
		return err
	}
	if err := audit.AppendOutbox(ctx, q, r.OrgID, event, types.RolloutPayload{
		OrgID: r.OrgID, RolloutID: r.ID, State: to, Stage: stage,
	}); err != nil {
		return err
	}
	r.State, r.CurrentStage, r.GateContext = to, stage, gateCtx
	return nil
}

// StartRollout moves a pending rollout to running and takes the first
// advance step (before-gate of stage 0, or immediate fan-out).
func (s *Service) StartRollout(ctx context.Context, actor, orgID, id string) (*types.Rollout, error) {
	r, err := s.GetRollout(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.transition(ctx, tx, r, types.RolloutStateRunning, 0, nil, actor)
	})
	if err != nil {
		return nil, err
	}
	if err := s.advance(ctx, r.ID); err != nil {
		return nil, err
	}
	return s.GetRollout(ctx, orgID, id)
}

// StopRollout pauses a running/gated rollout (§5.11 stop).
func (s *Service) StopRollout(ctx context.Context, actor, orgID, id string) (*types.Rollout, error) {
	r, err := s.GetRollout(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.transition(ctx, tx, r, types.RolloutStatePaused, r.CurrentStage, r.GateContext, actor)
	})
	if err != nil {
		return nil, err
	}
	return s.GetRollout(ctx, orgID, id)
}

// ResumeRollout re-enters a paused rollout (§5.11 resume).
func (s *Service) ResumeRollout(ctx context.Context, actor, orgID, id string) (*types.Rollout, error) {
	r, err := s.GetRollout(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	// A rollout paused while parked on a gate resumes into the gate, not
	// past it: resuming directly into running would skip a before-gate
	// entirely or re-request an after-gate approval.
	to := types.RolloutStateRunning
	if r.GateContext != nil {
		to = types.RolloutStateWaitingGate
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.transition(ctx, tx, r, to, r.CurrentStage, r.GateContext, actor)
	})
	if err != nil {
		return nil, err
	}
	if err := s.advance(ctx, r.ID); err != nil {
		return nil, err
	}
	return s.GetRollout(ctx, orgID, id)
}

// clearGate resumes a satisfied gate: a before-gate re-enters the same
// stage; an after-gate advances to the next stage.
func (s *Service) clearGate(ctx context.Context, r *types.Rollout) error {
	next := r.CurrentStage
	if r.GateContext != nil && r.GateContext.Gate == "after" {
		next++
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.transition(ctx, tx, r, types.RolloutStateRunning, next, nil, "system:fleetmanager")
	})
}

// gateApproved resumes a rollout whose approval gate was granted (called by
// the approval.decided resume handler). A rollout paused while parked on
// the gate is resumed too: the approval is an explicit decision to proceed,
// and ignoring it would park the rollout on an already-decided approval
// forever.
func (s *Service) gateApproved(ctx context.Context, rolloutID string, stage int, gate string) error {
	r, err := s.store.getRollout(ctx, s.db.Pool, rolloutID)
	if err != nil {
		return err
	}
	if r.CurrentStage != stage || r.GateContext == nil || r.GateContext.Gate != gate {
		return nil // stale or already resumed — idempotent
	}
	if r.State != types.RolloutStateWaitingGate && r.State != types.RolloutStatePaused {
		return nil
	}
	return s.clearGate(ctx, r)
}

// gateRejected fails a rollout whose approval gate was rejected. A rollout
// paused while parked on the gate is failed too — otherwise resuming would
// re-enter waiting_gate on an already-decided approval and park forever.
func (s *Service) gateRejected(ctx context.Context, rolloutID string, stage int) error {
	r, err := s.store.getRollout(ctx, s.db.Pool, rolloutID)
	if err != nil {
		return err
	}
	if r.CurrentStage != stage || r.GateContext == nil {
		return nil
	}
	if r.State != types.RolloutStateWaitingGate && r.State != types.RolloutStatePaused {
		return nil
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.transition(ctx, tx, r, types.RolloutStateFailed, r.CurrentStage, r.GateContext, "system:approvals")
	})
}

// commandFor builds the desired-state command for one target cluster. The
// command ID is the idempotency key (at-least-once delivery).
func (s *Service) commandFor(r *types.Rollout, stage int, clusterID, version string) (*types.AgentCommand, error) {
	payload, err := json.Marshal(map[string]string{
		"rolloutId":      r.ID,
		"kind":           r.Kind,
		"targetRef":      r.TargetRef,
		"desiredVersion": version,
	})
	if err != nil {
		return nil, err
	}
	suffix := "apply"
	if version != r.DesiredVersion {
		suffix = "rollback"
	}
	return &types.AgentCommand{
		ID:        fmt.Sprintf("rollout:%s:%d:%s:%s", r.ID, stage, clusterID, suffix),
		ClusterID: clusterID,
		Type:      "inari.fleet.RolloutApply",
		Payload:   payload,
	}, nil
}

// stageMembers resolves the union of member clusters across a stage's sets.
func (s *Service) stageMembers(ctx context.Context, orgID string, st types.RolloutStage) ([]types.Cluster, error) {
	seen := map[string]bool{}
	var out []types.Cluster
	for _, setID := range st.ClusterSetIDs {
		members, err := s.ClusterSetMembers(ctx, orgID, setID)
		if err != nil {
			return nil, err
		}
		for _, c := range members {
			if !seen[c.ID] {
				seen[c.ID] = true
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// enterGate parks the rollout on a before/after-stage gate.
func (s *Service) enterGate(ctx context.Context, r *types.Rollout, stage int, which string, g *types.RolloutStageGate) error {
	gc := &types.RolloutGateContext{Gate: which, Type: g.Type, WaitSeconds: g.WaitSeconds, EnteredAt: s.now()}
	if err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.transition(ctx, tx, r, types.RolloutStateWaitingGate, stage, gc, "system:fleetmanager")
	}); err != nil {
		return err
	}
	if g.Type == "approval" {
		return s.requestGateApproval(ctx, r)
	}
	return nil
}

// requestGateApproval creates the Approvals request for a parked approval
// gate after the waiting_gate transition has committed, then links it into
// the gate context. Post-commit creation avoids orphan approvals when the
// transition rolls back; advance retries while ApprovalID is empty, so a
// failed request is recovered by the next sweep.
func (s *Service) requestGateApproval(ctx context.Context, r *types.Rollout) error {
	if s.gates == nil {
		return fmt.Errorf("fleetmanager: approval gate configured but no gate requester wired")
	}
	gc := r.GateContext
	if r.State != types.RolloutStateWaitingGate || gc == nil || gc.Type != "approval" || gc.ApprovalID != "" {
		return nil // stale or already linked — idempotent
	}
	spec, _ := json.Marshal(map[string]any{
		"rolloutId": r.ID, "stage": r.CurrentStage, "gate": gc.Gate,
	})
	req, err := s.gates.RequestLifecycleApproval(ctx, approvals.LifecycleApprovalInput{
		OrgID: r.OrgID, Action: types.ApprovalActionRolloutStageGate,
		Requester: "system:fleetmanager", Context: spec,
	})
	if err != nil {
		return err
	}
	linked, err := s.store.setGateApproval(ctx, s.db.Pool, r.ID, r.CurrentStage, gc.Gate, req.ID)
	if err != nil {
		return err
	}
	if linked {
		gc.ApprovalID = req.ID
	}
	// !linked: the rollout moved concurrently; the orphan approval's later
	// decision is a no-op via the idempotency check in gateApproved.
	return nil
}

// advance drives the rollout until it parks (gate/pause/terminal) or makes
// no more progress. Idempotent; called by the run loop, Start/Resume, and
// the approval resume handler.
func (s *Service) advance(ctx context.Context, rolloutID string) error {
	// Bounded: each iteration either parks the rollout or advances a stage.
	for range maxAdvanceSteps {
		done, err := s.advanceOnce(ctx, rolloutID)
		if err != nil || done {
			return err
		}
	}
	return nil
}

// maxAdvanceSteps bounds one advance call (stages + slack).
const maxAdvanceSteps = 64

// advanceOnce performs one state-machine step. done=true means the rollout
// is parked (gated, waiting on agents, paused, or terminal).
func (s *Service) advanceOnce(ctx context.Context, rolloutID string) (done bool, err error) {
	r, err := s.store.getRollout(ctx, s.db.Pool, rolloutID)
	if err != nil {
		return true, err
	}
	switch r.State {
	case types.RolloutStateRunning:
		// proceed below
	case types.RolloutStateWaitingGate:
		gc := r.GateContext
		if gc == nil {
			return true, s.clearGate(ctx, r)
		}
		if gc.Type == "approval" && gc.ApprovalID == "" {
			return true, s.requestGateApproval(ctx, r) // recover a failed post-commit request
		}
		if gc.Type == "wait" && !s.now().Before(gc.EnteredAt.Add(time.Duration(gc.WaitSeconds)*time.Second)) {
			return true, s.clearGate(ctx, r)
		}
		return true, nil // still gated (approval pending or wait unexpired)
	default:
		return true, nil // paused/failed/completed/rolled_back: nothing to do
	}

	stage := r.CurrentStage
	if stage >= len(r.Stages) {
		return true, s.db.WithTx(ctx, func(tx pgx.Tx) error {
			return s.transition(ctx, tx, r, types.RolloutStateCompleted, stage, nil, "system:fleetmanager")
		})
	}
	st := r.Stages[stage]

	// Freshly entered the stage (no targets yet): seed targets, then gate or
	// deliver.
	targets, err := s.store.listTargets(ctx, s.db.Pool, r.ID, stage)
	if err != nil {
		return true, err
	}
	if len(targets) == 0 {
		members, err := s.stageMembers(ctx, r.OrgID, st)
		if err != nil {
			return true, err
		}
		if len(members) == 0 {
			return true, s.fail(ctx, r, "stage has no member clusters")
		}
		// Seed all stage targets as pending first: a cleared before-gate
		// resumes into existing pending targets instead of re-entering the
		// gate.
		for _, c := range members {
			t := &types.RolloutTarget{RolloutID: r.ID, ClusterID: c.ID, Stage: stage, Status: types.RolloutTargetPending}
			if err := s.store.upsertTarget(ctx, s.db.Pool, t); err != nil {
				return true, err
			}
		}
		if st.BeforeGate != nil {
			return true, s.enterGate(ctx, r, stage, "before", st.BeforeGate)
		}
		n, err := ParseMaxConcurrency(st.MaxConcurrency, len(members))
		if err != nil {
			return true, err
		}
		return true, s.deliverBatch(ctx, r, stage, n)
	}

	// Reconcile target health from command acks.
	ids := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.CommandID != "" && t.Status == types.RolloutTargetDelivered {
			ids = append(ids, t.CommandID)
		}
	}
	statuses, err := s.store.commandStatuses(ctx, s.db.Pool, ids)
	if err != nil {
		return true, err
	}
	pending, active, failed := 0, 0, 0
	for i := range targets {
		t := &targets[i]
		switch t.Status {
		case types.RolloutTargetPending:
			pending++
		case types.RolloutTargetDelivered:
			switch statuses[t.CommandID] {
			case types.CommandStatusAcked:
				if err := s.store.setTargetStatus(ctx, s.db.Pool, r.ID, t.ClusterID, stage, types.RolloutTargetHealthy, "healthy"); err != nil {
					return true, err
				}
			case types.CommandStatusNacked:
				if err := s.store.setTargetStatus(ctx, s.db.Pool, r.ID, t.ClusterID, stage, types.RolloutTargetFailed, "unhealthy"); err != nil {
					return true, err
				}
				failed++
			default:
				active++
			}
		case types.RolloutTargetFailed:
			failed++
		}
	}
	if failed > 0 {
		return true, s.fail(ctx, r, fmt.Sprintf("stage %d: %d target(s) failed", stage, failed))
	}
	if pending+active > 0 {
		// Top up the in-flight batch to the concurrency bound, then park
		// until the next sweep (agents report acks asynchronously).
		members, err := s.stageMembers(ctx, r.OrgID, st)
		if err != nil {
			return true, err
		}
		n, err := ParseMaxConcurrency(st.MaxConcurrency, len(members))
		if err != nil {
			return true, err
		}
		return true, s.deliverBatch(ctx, r, stage, n-active)
	}

	// Stage fully healthy: after-gate, then continue into the next stage in
	// the same advance call.
	if st.AfterGate != nil {
		return true, s.enterGate(ctx, r, stage, "after", st.AfterGate)
	}
	if err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.transition(ctx, tx, r, types.RolloutStateRunning, stage+1, nil, "system:fleetmanager")
	}); err != nil {
		return true, err
	}
	return false, nil
}

// deliverBatch enqueues desired-state commands for up to `slots` pending
// targets of the stage.
func (s *Service) deliverBatch(ctx context.Context, r *types.Rollout, stage, slots int) error {
	if slots <= 0 {
		return nil
	}
	targets, err := s.store.listTargets(ctx, s.db.Pool, r.ID, stage)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if slots == 0 {
			break
		}
		if t.Status != types.RolloutTargetPending {
			continue
		}
		cmd, err := s.commandFor(r, stage, t.ClusterID, r.DesiredVersion)
		if err != nil {
			return err
		}
		if err := s.queue.Enqueue(ctx, cmd); err != nil {
			return err
		}
		if err := s.store.upsertTarget(ctx, s.db.Pool, &types.RolloutTarget{
			RolloutID: r.ID, ClusterID: t.ClusterID, Stage: stage,
			Status: types.RolloutTargetDelivered, CommandID: cmd.ID,
		}); err != nil {
			return err
		}
		slots--
	}
	return nil
}

func (s *Service) fail(ctx context.Context, r *types.Rollout, reason string) error {
	slog.Warn("rollout failed", "rollout", r.ID, "reason", reason)
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		return s.transition(ctx, tx, r, types.RolloutStateFailed, r.CurrentStage, r.GateContext, "system:fleetmanager")
	})
}

// Rollback re-enqueues the previous version across all stage members in
// reverse stage order, then marks the rollout rolled_back (§5.11
// rollback-to-previous-version). Desired state only — agents apply it.
func (s *Service) Rollback(ctx context.Context, actor, orgID, id, toVersion string) (*types.Rollout, error) {
	if toVersion == "" {
		return nil, fmt.Errorf("%w: toVersion is required", ErrInvalidInput)
	}
	r, err := s.GetRollout(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if r.State == types.RolloutStatePending || r.State == types.RolloutStateRolledBack {
		return nil, fmt.Errorf("%w: %s → rolled_back", ErrInvalidTransition, r.State)
	}
	if toVersion == r.DesiredVersion {
		// The rollback command IDs would collide with the original apply
		// commands (idempotency keys) and be silently dropped by the queue.
		return nil, fmt.Errorf("%w: toVersion must differ from the desired version", ErrInvalidInput)
	}
	for stage := len(r.Stages) - 1; stage >= 0; stage-- {
		members, err := s.stageMembers(ctx, orgID, r.Stages[stage])
		if err != nil {
			return nil, err
		}
		for _, c := range members {
			cmd, err := s.commandFor(r, stage, c.ID, toVersion)
			if err != nil {
				return nil, err
			}
			if err := s.queue.Enqueue(ctx, cmd); err != nil {
				return nil, err
			}
		}
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if !CanRolloutTransition(r.State, types.RolloutStateRolledBack) {
			return fmt.Errorf("%w: %s → rolled_back", ErrInvalidTransition, r.State)
		}
		return s.transition(ctx, tx, r, types.RolloutStateRolledBack, r.CurrentStage, nil, actor)
	})
	if err != nil {
		return nil, err
	}
	return s.GetRollout(ctx, orgID, id)
}

// AdvanceSweep advances every active rollout once. Returns the count
// advanced. Runs on a ticker from main (see RunAdvanceLoop).
func (s *Service) AdvanceSweep(ctx context.Context) (int, error) {
	active, err := s.store.listActiveRollouts(ctx, s.db.Pool)
	if err != nil {
		return 0, err
	}
	for i := range active {
		if err := s.advance(ctx, active[i].ID); err != nil && ctx.Err() == nil {
			slog.Warn("rollout advance failed", "rollout", active[i].ID, "error", err)
		}
	}
	return len(active), nil
}

// RunAdvanceLoop runs AdvanceSweep on an interval until ctx is cancelled.
func (s *Service) RunAdvanceLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if _, err := s.AdvanceSweep(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("rollout advance sweep failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
