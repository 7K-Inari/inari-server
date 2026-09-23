// Approval-decision resume for tenant decommission (ADR-0006, mirrors
// tenantzonefactory.ResumeHandler): an approved tenant.decommission runs
// the teardown state machine; a rejection restores the org to active.
package tenancy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/7K-Inari/inari-server/internal/types"
)

// DeletionApprovalLoader loads a decided approval request
// (approvals.Service seam, defined here to avoid an import cycle).
type DeletionApprovalLoader interface {
	Get(ctx context.Context, orgID, approvalID string) (*types.ApprovalRequest, error)
}

// DeletionResumeHandler implements audit.Handler for EventApprovalDecided.
type DeletionResumeHandler struct {
	svc       *Service
	deleter   *Deleter
	approvals DeletionApprovalLoader
	log       *slog.Logger
}

// NewDeletionResumeHandler builds the dispatcher handler.
func NewDeletionResumeHandler(svc *Service, deleter *Deleter, approvals DeletionApprovalLoader, log *slog.Logger) *DeletionResumeHandler {
	if log == nil {
		log = slog.Default()
	}
	return &DeletionResumeHandler{svc: svc, deleter: deleter, approvals: approvals, log: log}
}

// EventTypes implements audit.Handler.
func (h *DeletionResumeHandler) EventTypes() []string {
	return []string{types.EventApprovalDecided, types.EventApprovalCancelled}
}

// Handle starts teardown on approval or restores the org on denial.
func (h *DeletionResumeHandler) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var p types.ApprovalPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("tenancy: deletion resume: payload: %w", err)
	}
	req, err := h.approvals.Get(ctx, p.OrgID, p.ApprovalID)
	if err != nil {
		return fmt.Errorf("tenancy: deletion resume: load approval %s: %w", p.ApprovalID, err)
	}
	if req.Action != types.ApprovalActionTenantDecommission {
		return nil // not ours
	}
	var lc struct {
		OrgID string `json:"orgId"`
		Slug  string `json:"slug"`
	}
	if err := json.Unmarshal(req.Spec, &lc); err != nil || lc.OrgID == "" {
		return fmt.Errorf("tenancy: deletion resume: approval %s missing org context", p.ApprovalID)
	}
	switch p.State {
	case types.ApprovalStateApproved:
		return h.deleter.Run(ctx, lc.OrgID)
	case types.ApprovalStateCancelled:
		return h.svc.abortDeletion(ctx, lc.OrgID, p.ApprovalID)
	default:
		return h.svc.denyDeletion(ctx, lc.OrgID, p.ApprovalID)
	}
}
