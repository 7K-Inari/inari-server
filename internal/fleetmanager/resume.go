// Approval-decision resume for rollout stage gates: consumes
// approval.decided outbox events and resumes (approved) or fails (rejected)
// the gated rollout, mirroring the orchestrator/TZF resume pattern.
package fleetmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/7K-Inari/inari-server/internal/types"
)

// ApprovalLoader loads a decided approval request (approvals.Service seam).
type ApprovalLoader interface {
	Get(ctx context.Context, orgID, approvalID string) (*types.ApprovalRequest, error)
}

// ResumeHandler implements audit.Handler for EventApprovalDecided, scoped
// to rollout stage-gate approvals (action rollout.stage_gate).
type ResumeHandler struct {
	svc       *Service
	approvals ApprovalLoader
	log       *slog.Logger
}

func NewResumeHandler(svc *Service, approvals ApprovalLoader, log *slog.Logger) *ResumeHandler {
	if log == nil {
		log = slog.Default()
	}
	return &ResumeHandler{svc: svc, approvals: approvals, log: log}
}

func (h *ResumeHandler) EventTypes() []string { return []string{types.EventApprovalDecided} }

type gateSpec struct {
	RolloutID string `json:"rolloutId"`
	Stage     int    `json:"stage"`
	Gate      string `json:"gate"`
}

func (h *ResumeHandler) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var p types.ApprovalPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("fleetmanager: resume: payload: %w", err)
	}
	req, err := h.approvals.Get(ctx, p.OrgID, p.ApprovalID)
	if err != nil {
		return fmt.Errorf("fleetmanager: resume: load approval %s: %w", p.ApprovalID, err)
	}
	if req.Action != types.ApprovalActionRolloutStageGate {
		return nil // not a rollout gate
	}
	var spec gateSpec
	if err := json.Unmarshal(req.Spec, &spec); err != nil {
		return fmt.Errorf("fleetmanager: resume: gate spec: %w", err)
	}
	if p.State == types.ApprovalStateApproved {
		h.log.Info("rollout stage gate approved", "rollout", spec.RolloutID, "stage", spec.Stage, "gate", spec.Gate)
		return h.svc.gateApproved(ctx, spec.RolloutID, spec.Stage, spec.Gate)
	}
	h.log.Info("rollout stage gate rejected", "rollout", spec.RolloutID, "stage", spec.Stage)
	return h.svc.gateRejected(ctx, spec.RolloutID, spec.Stage)
}
