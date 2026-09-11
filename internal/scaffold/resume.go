// Approval-decision resume (M8.W6, parent plan §5.3 — mirrors
// orchestrator/resume.go): consumes approval.decided outbox events for
// template (item ID prefix "template:") requests. An approved request
// flips the parked run from pending_approval back to its next phase so the
// reconcile loop claims it; a rejected/expired request settles the run
// failed. The resumed run executes as control-plane automation
// impersonating the tenant-scoped virtual user, so the audit trail records
// both identities (§5.4).
package scaffold

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/impersonation"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ApprovalLoader loads a decided approval request (approvals.Service seam).
type ApprovalLoader interface {
	Get(ctx context.Context, orgID, approvalID string) (*types.ApprovalRequest, error)
}

// ResumeHandler implements audit.Handler for EventApprovalDecided.
type ResumeHandler struct {
	svc       *Service
	approvals ApprovalLoader
	log       *slog.Logger
}

// NewResumeHandler builds the dispatcher handler.
func NewResumeHandler(svc *Service, approvals ApprovalLoader, log *slog.Logger) *ResumeHandler {
	if log == nil {
		log = slog.Default()
	}
	return &ResumeHandler{svc: svc, approvals: approvals, log: log}
}

// EventTypes implements audit.Handler.
func (h *ResumeHandler) EventTypes() []string { return []string{types.EventApprovalDecided} }

// Handle resumes (or settles) the gated scaffold run.
func (h *ResumeHandler) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var p types.ApprovalPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("scaffold: resume: payload: %w", err)
	}
	req, err := h.approvals.Get(ctx, p.OrgID, p.ApprovalID)
	if err != nil {
		return fmt.Errorf("scaffold: resume: load approval %s: %w", p.ApprovalID, err)
	}
	if !strings.HasPrefix(req.ItemID, "template:") {
		return nil // not ours (catalog deploys and lifecycle gates resume elsewhere)
	}
	var spec struct {
		RunID string `json:"runId"`
	}
	if err := json.Unmarshal(req.Spec, &spec); err != nil || spec.RunID == "" {
		return fmt.Errorf("scaffold: resume: approval %s missing run context", p.ApprovalID)
	}
	run, err := h.svc.store.GetRun(ctx, h.svc.db.Pool, req.OrgID, spec.RunID)
	if err != nil {
		return err
	}
	if run.Phase != types.ScaffoldPhasePendingApproval {
		return nil // already resumed or settled (duplicate delivery / cancel)
	}
	actor := "system:approvals"
	if p.State != types.ApprovalStateApproved {
		return h.svc.finalize(ctx, run, types.ScaffoldPhaseFailed,
			fmt.Sprintf("approval %s %s", p.ApprovalID, p.State),
			types.EventScaffoldRunFailed, actor)
	}
	steps, err := h.svc.store.ListSteps(ctx, h.svc.db.Pool, run.ID)
	if err != nil {
		return err
	}
	next := nextPhaseForRun(steps)
	// The approval hold marker (outputs.approvalId) is kept so a re-driven
	// run never requests a second approval.
	// Double-audit: the real actor is the approvals automation; the
	// impersonated identity is the tenant-scoped virtual user (§5.4).
	ctx = impersonation.WithImpersonator(ctx, impersonation.VirtualUser(req.OrgID))
	run.Phase = next
	err = h.svc.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := h.svc.store.UpdateRunPhase(ctx, tx, run.ID, next, "", nil); err != nil {
			return err
		}
		if err := h.svc.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: run.OrgID, Actor: actor, Action: "scaffold.run_resumed",
			ObjectType: "scaffold_run", ObjectID: run.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"approvalId":%q,"phase":%q}`, p.ApprovalID, next)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, run.OrgID, types.EventScaffoldRunStepUpdated, types.ScaffoldRunPayload{
			OrgID: run.OrgID, RunID: run.ID, Version: run.TemplateVersion, Phase: string(next),
		})
	})
	if err != nil {
		return err
	}
	h.log.Info("scaffold: approval-gated run resumed", "approval", p.ApprovalID, "run", run.ID, "phase", next)
	return nil
}
