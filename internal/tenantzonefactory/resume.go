// Approval-decision resume (plan §5.12, mirrors orchestrator.ResumeHandler):
// an approved tenant_zone.vend starts provisioning; an approved
// tenant_zone.decommission starts the reverse flow. Rejections settle the
// zone to failed/closed-request-denied.
package tenantzonefactory

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

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

// Handle resumes the gated zone operation on approval.
func (h *ResumeHandler) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	var p types.ApprovalPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return fmt.Errorf("tzf: resume: payload: %w", err)
	}
	req, err := h.approvals.Get(ctx, p.OrgID, p.ApprovalID)
	if err != nil {
		return fmt.Errorf("tzf: resume: load approval %s: %w", p.ApprovalID, err)
	}
	if req.Action != types.ApprovalActionTenantZoneVend && req.Action != types.ApprovalActionTenantZoneDecommission {
		return nil // not ours (catalog deploy approvals resume elsewhere)
	}
	var lc struct {
		ZoneID string `json:"zoneId"`
	}
	if err := json.Unmarshal(req.Spec, &lc); err != nil || lc.ZoneID == "" {
		return fmt.Errorf("tzf: resume: approval %s missing zone context", p.ApprovalID)
	}
	if p.State != types.ApprovalStateApproved {
		zone, err := h.svc.store.GetZone(ctx, h.svc.db.Pool, lc.ZoneID)
		if err != nil {
			return err
		}
		if req.Action == types.ApprovalActionTenantZoneDecommission {
			// Decommission denied: the zone returns to active service.
			return h.svc.setState(ctx, zone, types.ZoneStateActive, "")
		}
		return h.svc.settle(ctx, zone, types.ZoneStateFailed, types.EventTenantZoneFailed, "system:approvals",
			fmt.Errorf("approval %s %s", p.ApprovalID, p.State))
	}
	// Double-audit: automation acts as itself impersonating the platform
	// org's virtual user (§5.4).
	ctx = impersonation.WithImpersonator(ctx, impersonation.VirtualUser(req.OrgID))
	switch req.Action {
	case types.ApprovalActionTenantZoneVend:
		return h.svc.StartProvisioning(ctx, lc.ZoneID, "system:approvals")
	case types.ApprovalActionTenantZoneDecommission:
		return h.svc.StartDecommission(ctx, lc.ZoneID, "system:approvals")
	}
	return nil
}
